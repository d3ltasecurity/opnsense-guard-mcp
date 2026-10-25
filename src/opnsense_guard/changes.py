"""Applying plans, with verification and automatic revert (OPNsense 26.7+).

OPNsense 26.7 removed the filter savepoint API, so rollback is done here at
object level:

    re-read (drift check) -> journal before-state -> write -> apply ->
    read back + verify -> health probe -> pending, revert timer running

``change_confirm`` keeps a change; otherwise it is reverted when the timer
fires, on ``change_rollback``, when the server shuts down, or when it starts
again after a crash. A revert never overwrites an object someone else has
edited in the meantime: that change is marked ``conflict`` instead.

Honest limit: the timer runs on this host. If a change cuts this host off from
the firewall API, the revert cannot reach it. The anti-lockout policy and the
health probe right after apply are there to prevent and catch exactly that.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable
from typing import Any

from opnsense_guard.audit import AuditLog
from opnsense_guard.client import OPNsenseError, ReadClient, WriteClient
from opnsense_guard.journal import Change, ChangeObject, Journal, new_change_id
from opnsense_guard.planner import (
    ALIAS_FIELDS,
    RULE_FIELDS,
    Planner,
    PlanStore,
    alias_view,
)
from opnsense_guard.policy import Policy

HEALTH_PATH = "/api/core/firmware/status"
COMMIT_PATH = {"rule": "/api/firewall/filter/apply", "alias": "/api/firewall/alias/reconfigure"}


class ChangeError(RuntimeError):
    """A change could not be applied; partial work has been reverted."""


def _fields(kind: str) -> tuple[str, ...]:
    return RULE_FIELDS if kind == "rule" else ALIAS_FIELDS


def _same(kind: str, current: dict[str, Any] | None, expected: dict[str, Any] | None) -> bool:
    """True if the firewall object matches what we expect (planned or read back)."""
    if current is None or expected is None:
        return current is expected
    return not _differences(kind, expected, current)


# Fields the plan may leave empty for OPNsense to fill in (a new rule's sequence).
FILLED_BY_FIREWALL = {"sequence"}


def _differences(kind: str, want: dict[str, Any], got: dict[str, Any] | None) -> list[str]:
    if got is None:
        return ["object not found after write"]
    return [
        f"{f}: expected {want.get(f, '')!r}, firewall has {got.get(f, '')!r}"
        for f in _fields(kind)
        if str(want.get(f, "")) != str(got.get(f, ""))
        and not (f in FILLED_BY_FIREWALL and want.get(f, "") == "")
    ]


def _alias_body(state: dict[str, Any], name: str) -> dict[str, Any]:
    return {
        "alias": {
            "enabled": "1",
            "name": name,
            "type": state["type"],
            "content": "\n".join(e for e in str(state["entries"]).split(",") if e),
            "description": state["description"],
        }
    }


class ChangeManager:
    def __init__(
        self,
        policy: Policy,
        planner: Planner,
        store: PlanStore,
        journal: Journal,
        audit: AuditLog,
        get_read: Callable[[], ReadClient],
        get_write: Callable[[], WriteClient],
        timeout_s: float | None = None,
    ) -> None:
        self.policy = policy
        self.planner = planner
        self.store = store
        self.journal = journal
        self.audit = audit
        self.get_read = get_read
        self.get_write = get_write
        self.timeout_s = timeout_s if timeout_s is not None else policy.writes.confirm_timeout_s
        self._lock = asyncio.Lock()
        self._timers: dict[str, asyncio.Task[None]] = {}

    # ----------------------------------------------------------- reading

    async def _current(self, obj: ChangeObject) -> dict[str, Any] | None:
        """Current state of the object on the firewall (None = absent)."""
        if obj.type == "rule":
            uuid = obj.reverted_uuid or obj.uuid
            if not uuid:
                return None
            state, error = await self.planner.get_rule(uuid)
            if error and "not found" not in error:
                raise OPNsenseError(error)
            return state
        current, error = await self.planner.get_alias(obj.ref)
        if error:
            raise OPNsenseError(error)
        return alias_view(current)

    # ----------------------------------------------------------- writing

    async def _write(self, kind: str, obj: ChangeObject) -> None:
        w = self.get_write()
        planned = obj.planned or {}
        before = obj.before or {}
        if kind == "rule":
            if obj.op == "add":
                fields = {f: planned[f] for f in RULE_FIELDS}
                if not fields["sequence"]:
                    del fields["sequence"]  # let OPNsense choose
                result = await w.post("/api/firewall/filter/addRule", {"rule": fields})
                obj.uuid = result.get("uuid") if isinstance(result, dict) else None
                if not obj.uuid:
                    raise ChangeError(f"addRule returned no uuid: {result}")
            elif obj.op == "update":
                changed = {f: planned[f] for f in RULE_FIELDS if planned[f] != before.get(f)}
                await w.post(f"/api/firewall/filter/setRule/{obj.uuid}", {"rule": changed})
            elif obj.op == "toggle":
                await w.post(f"/api/firewall/filter/toggleRule/{obj.uuid}/{planned['enabled']}")
            elif obj.op == "delete":
                await w.post(f"/api/firewall/filter/delRule/{obj.uuid}")
        else:
            if obj.op == "create":
                result = await w.post("/api/firewall/alias/addItem", _alias_body(planned, obj.ref))
                obj.uuid = result.get("uuid") if isinstance(result, dict) else None
                if not obj.uuid:
                    raise ChangeError(f"addItem returned no uuid: {result}")
            elif obj.op in ("add_entries", "remove_entries"):
                content = "\n".join(e for e in planned["entries"].split(",") if e)
                await w.post(
                    f"/api/firewall/alias/setItem/{obj.uuid}", {"alias": {"content": content}}
                )
            elif obj.op == "delete":
                await w.post(f"/api/firewall/alias/delItem/{obj.uuid}")
        obj.done = True

    async def _undo(self, kind: str, obj: ChangeObject, current: dict[str, Any] | None) -> None:
        w = self.get_write()
        before = obj.before or {}
        if kind == "rule":
            if obj.op == "add":
                await w.post(f"/api/firewall/filter/delRule/{obj.uuid}")
            elif obj.op == "delete":
                body = {"rule": {f: before[f] for f in RULE_FIELDS}}
                result = await w.post("/api/firewall/filter/addRule", body)
                obj.reverted_uuid = result.get("uuid") if isinstance(result, dict) else None
            elif obj.op == "toggle":
                await w.post(f"/api/firewall/filter/toggleRule/{obj.uuid}/{before['enabled']}")
            else:
                current = current or {}
                restore = {f: before[f] for f in RULE_FIELDS if before[f] != current.get(f)}
                await w.post(f"/api/firewall/filter/setRule/{obj.uuid}", {"rule": restore})
        else:
            if obj.op == "create":
                await w.post(f"/api/firewall/alias/delItem/{obj.uuid}")
            elif obj.op == "delete":
                result = await w.post("/api/firewall/alias/addItem", _alias_body(before, obj.ref))
                obj.reverted_uuid = result.get("uuid") if isinstance(result, dict) else None
            else:
                content = "\n".join(e for e in before["entries"].split(",") if e)
                await w.post(
                    f"/api/firewall/alias/setItem/{obj.uuid}", {"alias": {"content": content}}
                )

    # -------------------------------------------------------------- apply

    def _refuse(self, message: str, **extra: Any) -> dict[str, Any]:
        return {"status": "refused", "error": message, **extra}

    async def apply(self, plan_id: str, actor: str, confirm_method: str) -> dict[str, Any]:
        plan = self.store.get(plan_id)
        if plan is None:
            return self._refuse(f"no plan {plan_id} (unknown, or expired after 15 minutes)")
        if not plan.allowed:
            return self._refuse("plan was denied by policy; fix it and plan again")
        if self.journal.plan_used(plan_id):
            return self._refuse("this plan was already applied; plan again for a new change")
        if plan.policy_sha256 != self.policy.sha256:
            return self._refuse("policy changed since this plan was made; plan again")

        async with self._lock:
            open_changes = self.journal.open_changes()
            if open_changes:
                return self._refuse(
                    f"change {open_changes[0].id} is still pending: confirm or roll it back first"
                )
            per_hour = self.policy.writes.max_changes_per_hour
            if self.journal.count_since(time.time() - 3600) >= per_hour:
                return self._refuse(f"rate limit: max_changes_per_hour is {per_hour}")

            change = Change(
                id=new_change_id(),
                plan_id=plan.id,
                kind=plan.kind,
                actor=actor,
                status="applying",
                created=time.time(),
                deadline=None,
                confirm_method=confirm_method,
                objects=[
                    ChangeObject(
                        type=o.type,
                        op=o.op,
                        ref=o.ref,
                        before=o.before,
                        planned=o.after,
                        uuid=(
                            o.ref
                            if o.type == "rule" and o.ref != "(new)"
                            else (o.before or {}).get("uuid")
                        ),
                    )
                    for o in plan.objects
                ],
            )

            # Drift check: the firewall must still look like it did at plan time.
            try:
                for obj in change.objects:
                    if obj.op in ("add", "create") and obj.type == "rule":
                        continue
                    current = await self._current(obj)
                    expected = obj.before
                    if not _same(plan.kind, current, expected):
                        return self._refuse(
                            f"{obj.type} {obj.ref} changed on the firewall since it was planned; "
                            "plan again",
                            plan_id=plan.id,
                        )
            except OPNsenseError as exc:
                return self._refuse(f"could not re-read the firewall before applying: {exc}")

            self.journal.save(change)  # before anything is sent
            self.audit.append(
                "change_applying",
                change_id=change.id,
                plan_id=plan.id,
                actor=actor,
                confirm_method=confirm_method,
                objects=[{"type": o.type, "op": o.op, "ref": o.ref} for o in change.objects],
            )

            try:
                for obj in change.objects:
                    await self._write(change.kind, obj)
                    self.journal.save(change)
                await self.get_write().post(COMMIT_PATH[change.kind])

                problems: list[str] = []
                for obj in change.objects:
                    obj.after = await self._current(obj)
                    if obj.op == "delete":
                        if obj.after is not None:
                            problems.append(f"{obj.type} {obj.ref} still exists after delete")
                    else:
                        problems += _differences(change.kind, obj.planned or {}, obj.after)
                self.journal.save(change)
                if problems:
                    raise ChangeError("verification failed: " + "; ".join(problems))

                try:
                    await self.get_read().get(HEALTH_PATH)
                except OPNsenseError as exc:
                    raise ChangeError(
                        f"health probe failed after apply ({exc}); this server may have "
                        "lost API access, reverting now"
                    ) from exc
            except (OPNsenseError, ChangeError) as exc:
                change.error = str(exc)
                await self._revert(change, reason="apply failed", final="failed")
                clean = change.status == "failed"
                return {
                    "status": change.status,
                    "change_id": change.id,
                    "error": change.error,
                    "note": (
                        "The change was not kept. Everything already written was reverted."
                        if clean
                        else "The change failed AND could not be fully reverted. Check the "
                        "firewall by hand; see change_get for what was written."
                    ),
                }

            change.status = "pending"
            change.deadline = time.time() + self.timeout_s
            self.journal.save(change)
            self._schedule(change)
            self.audit.append(
                "change_applied",
                change_id=change.id,
                plan_id=plan.id,
                actor=actor,
                revert_deadline=change.deadline,
                objects=[
                    {"type": o.type, "op": o.op, "ref": o.ref, "uuid": o.uuid, "after": o.after}
                    for o in change.objects
                ],
            )
            return {
                **change.to_dict(),
                "note": (
                    f"Applied and verified. It will be REVERTED automatically in "
                    f"{round(self.timeout_s)} s unless you call change_confirm "
                    f"with change_id {change.id}. Test it first."
                ),
            }

    # ------------------------------------------------------------- revert

    async def _revert(self, change: Change, reason: str, final: str = "reverted") -> None:
        """Undo every written object, newest first. Caller holds the lock."""
        self._cancel_timer(change.id)
        conflicts: list[str] = []
        errors: list[str] = []
        undone = 0
        for obj in reversed(change.objects):
            if not obj.done:
                continue
            try:
                current = await self._current(obj)
                expected = obj.after if obj.after is not None or obj.op == "delete" else obj.planned
                if obj.op == "delete":
                    ok = current is None
                else:
                    ok = _same(change.kind, current, expected)
                if not ok:
                    conflicts.append(f"{obj.type} {obj.ref} was changed by someone else")
                    continue
                await self._undo(change.kind, obj, current)
                undone += 1
            except (OPNsenseError, ChangeError) as exc:
                errors.append(f"{obj.type} {obj.ref}: {exc}")
        if undone:
            try:
                await self.get_write().post(COMMIT_PATH[change.kind])
            except OPNsenseError as exc:
                errors.append(f"apply after revert failed: {exc}")

        if errors:
            change.status = "revert_failed"
        elif conflicts:
            change.status = "conflict"
        else:
            change.status = final  # type: ignore[assignment]
        notes = [*conflicts, *errors]
        if notes:
            change.error = "; ".join(filter(None, [change.error, *notes]))
        change.deadline = None
        self.journal.save(change)
        self.audit.append(
            "change_reverted"
            if change.status in ("reverted", "failed")
            else "change_revert_problem",
            change_id=change.id,
            reason=reason,
            status=change.status,
            undone=undone,
            conflicts=conflicts,
            errors=errors,
        )

    # ------------------------------------------------- confirm / rollback

    async def confirm(self, change_id: str, actor: str) -> dict[str, Any]:
        async with self._lock:
            change = self.journal.get(change_id)
            if change is None:
                return self._refuse(f"no change {change_id}")
            if change.status != "pending":
                return self._refuse(f"change {change_id} is '{change.status}', not pending")
            self._cancel_timer(change_id)
            change.status = "confirmed"
            change.deadline = None
            self.journal.save(change)
            self.audit.append("change_confirmed", change_id=change_id, actor=actor)
            return {**change.to_dict(), "note": "Change kept."}

    async def rollback(self, change_id: str, actor: str) -> dict[str, Any]:
        async with self._lock:
            change = self.journal.get(change_id)
            if change is None:
                return self._refuse(f"no change {change_id}")
            if change.status not in ("pending", "confirmed"):
                return self._refuse(
                    f"change {change_id} is '{change.status}'; nothing to roll back"
                )
            await self._revert(change, reason=f"rollback by {actor}")
            return change.to_dict()

    async def revert_all_open(self, reason: str) -> list[dict[str, Any]]:
        """Revert every unconfirmed change (startup recovery and shutdown)."""
        results = []
        async with self._lock:
            for change in self.journal.open_changes():
                await self._revert(change, reason=reason)
                results.append(change.to_dict())
        return results

    # ------------------------------------------------------------- timers

    def _schedule(self, change: Change) -> None:
        delay = max(0.0, (change.deadline or time.time()) - time.time())
        self._timers[change.id] = asyncio.get_running_loop().create_task(
            self._expire_later(change.id, delay)
        )

    def _cancel_timer(self, change_id: str) -> None:
        task = self._timers.pop(change_id, None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _expire_later(self, change_id: str, delay: float) -> None:
        await asyncio.sleep(delay)
        async with self._lock:
            change = self.journal.get(change_id)
            if change is not None and change.status == "pending":
                await self._revert(change, reason="confirm timeout")
        self._timers.pop(change_id, None)

    async def aclose(self) -> None:
        for task in list(self._timers.values()):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._timers.clear()
