"""Change tools: apply a plan, confirm it, or roll it back.

Registered only when the policy is in write mode AND write credentials are
configured. Over HTTP they need a token with scope ``write``.
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from opnsense_guard.changes import ChangeManager
from opnsense_guard.policy import Policy
from opnsense_guard.tools.plan import actor_of, scope_of

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)
WRITES = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False)
KEEPS = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True)


class ApplyApproval(BaseModel):
    approve: bool = Field(description="Apply this firewall change now?")


def _needs_write(ctx: Context) -> dict[str, Any] | None:
    if scope_of(ctx) != "write":
        return {
            "status": "refused",
            "error": "this tool needs a token with scope 'write' (yours is read-only)",
        }
    return None


def _elicitation_supported(ctx: Context) -> bool:
    try:
        caps = ctx.client_capabilities
    except ValueError:
        return False
    return caps is not None and caps.elicitation is not None


def register_change_tools(mcp: MCPServer, manager: ChangeManager, policy: Policy) -> None:
    @mcp.tool(annotations=WRITES)
    async def change_apply(plan_id: str, ctx: Context, user_confirmed: bool = False) -> Any:
        """APPLY a plan to the firewall. This changes the live firewall.

        The change is verified, then REVERTED automatically after the policy
        timeout unless change_confirm is called. Only one change can be open
        at a time.

        Before calling: show the user the plan's diff and get a clear yes.
        If the client cannot show a confirmation prompt, pass
        user_confirmed=true ONLY after the user has said yes in the chat.

        Args:
            plan_id: id returned by rule_plan / alias_plan (valid 15 minutes).
            user_confirmed: the user approved this exact diff in the chat.
        """
        refused = _needs_write(ctx)
        if refused:
            return refused
        actor = actor_of(ctx)

        plan = manager.store.get(plan_id)
        if plan is None:
            return {"status": "refused", "error": f"no plan {plan_id} (unknown or expired)"}
        diff = "\n".join(line for o in plan.objects for line in o.diff)

        method = "not_required"
        if policy.writes.require_human_confirm:
            answer = None
            if _elicitation_supported(ctx):
                try:
                    answer = await ctx.elicit(
                        f"Apply this firewall change? It auto-reverts in "
                        f"{round(manager.timeout_s)} s unless confirmed.\n\n{diff}",
                        ApplyApproval,
                    )
                except Exception:
                    # Declaring the capability is not the same as being able to
                    # use it: an HTTP transport with no back-channel for
                    # server-initiated requests raises here. Fall back to the
                    # in-chat confirmation rather than failing the apply.
                    answer = None
            if answer is not None:
                approved = answer.action == "accept" and bool(
                    getattr(answer, "data", None) and answer.data.approve
                )
                if not approved:
                    manager.audit.append(
                        "change_declined", plan_id=plan_id, actor=actor, via="elicitation"
                    )
                    return {
                        "status": "declined",
                        "note": "The user did not approve. Nothing changed.",
                    }
                method = "elicitation"
            elif not user_confirmed:
                return {
                    "status": "needs_confirmation",
                    "diff": plan.to_dict()["diff"],
                    "note": (
                        "Show this diff to the user and ask for approval. Call change_apply "
                        "again with user_confirmed=true only if they say yes."
                    ),
                }
            else:
                method = "user_confirmed_in_chat"

        return await manager.apply(plan_id, actor, method)

    @mcp.tool(annotations=KEEPS)
    async def change_confirm(change_id: str, ctx: Context) -> Any:
        """KEEP an applied change: stops its automatic revert.

        Only confirm after the user has checked the change works as intended.
        """
        return _needs_write(ctx) or await manager.confirm(change_id, actor_of(ctx))

    @mcp.tool(annotations=WRITES)
    async def change_rollback(change_id: str, ctx: Context) -> Any:
        """REVERT a change now (pending or confirmed).

        Refuses to overwrite an object someone else changed since; the change
        is then marked 'conflict' for a human to look at.
        """
        return _needs_write(ctx) or await manager.rollback(change_id, actor_of(ctx))

    @mcp.tool(annotations=READ_ONLY)
    async def change_list(limit: int = 20) -> list[dict[str, Any]]:
        """Recent changes: pending (with seconds left), confirmed, reverted, failed.

        Args:
            limit: number of changes (1-100).
        """
        return [c.to_dict() for c in manager.journal.recent(max(1, min(int(limit), 100)))]

    @mcp.tool(annotations=READ_ONLY)
    async def change_get(change_id: str) -> Any:
        """One change with its before/after snapshots."""
        change = manager.journal.get(change_id)
        return change.to_dict() if change else {"error": f"no change {change_id}"}
