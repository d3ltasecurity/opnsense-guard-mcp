import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import respx
from pydantic import SecretStr

from fake_opnsense import FakeOPNsense
from opnsense_guard.audit import AuditLog, verify
from opnsense_guard.changes import ChangeManager
from opnsense_guard.client import PathNotAllowed, ReadClient, WriteClient, check_write_path
from opnsense_guard.config import ReadSettings
from opnsense_guard.journal import Journal
from opnsense_guard.planner import AliasOp, Planner, PlanStore, RuleOp
from opnsense_guard.policy import Policy, load_policy

ROOT = Path(__file__).resolve().parent.parent
BLOCK_SSH = {
    "action": "block",
    "interface": "opt1",
    "protocol": "TCP",
    "source_net": "192.168.50.0/24",
    "destination_net": "(self)",
    "destination_port": "22",
    "description": "DMZ may not SSH to firewall",
}


@pytest.fixture
def fw(api: respx.MockRouter) -> FakeOPNsense:
    fake = FakeOPNsense()
    fake.mount(api)
    return fake


@pytest.fixture
async def write_client() -> AsyncIterator[WriteClient]:
    settings = ReadSettings(
        url="https://fw.test", api_key=SecretStr("w-key"), api_secret=SecretStr("w-secret")
    )
    c = WriteClient(settings)
    yield c
    await c.aclose()


@pytest.fixture
def policy() -> Policy:
    return load_policy(ROOT / "policy.example.yaml")


@pytest.fixture
async def manager(
    tmp_path: Path, policy: Policy, client: ReadClient, write_client: WriteClient
) -> AsyncIterator[ChangeManager]:
    store = PlanStore()
    m = ChangeManager(
        policy,
        Planner(policy, lambda: client, store),
        store,
        Journal(tmp_path / "journal.sqlite"),
        AuditLog(tmp_path / "audit.jsonl"),
        lambda: client,
        lambda: write_client,
        timeout_s=30,
    )
    yield m
    await m.aclose()


async def plan_rules(m: ChangeManager, *ops: RuleOp) -> str:
    plan = await m.planner.plan_rules(list(ops), "stdio")
    assert plan.allowed, plan.to_dict()["violations"]
    return plan.id


def add(**rule: Any) -> RuleOp:
    return RuleOp(op="add", rule={**BLOCK_SSH, **rule})  # type: ignore[arg-type]


async def apply(m: ChangeManager, plan_id: str) -> dict[str, Any]:
    return await m.apply(plan_id, "stdio", "test")


# ---------------------------------------------------------------- happy path


async def test_apply_then_confirm(manager: ChangeManager, fw: FakeOPNsense) -> None:
    result = await apply(manager, await plan_rules(manager, add()))
    assert result["status"] == "pending", result
    assert "REVERTED automatically" in result["note"]
    assert len(fw.rules) == 1
    rule = next(iter(fw.rules.values()))
    assert rule["description"] == "[mcp] DMZ may not SSH to firewall"
    assert (rule["log"], rule["quick"], rule["source_not"]) == ("1", "1", "0")
    assert fw.applies == 1

    confirmed = await manager.confirm(result["id"], "stdio")
    assert confirmed["status"] == "confirmed"
    assert not manager._timers
    assert len(fw.rules) == 1

    events = [e["event"] for e in manager.audit.tail(10)]
    assert events[-3:] == ["change_applying", "change_applied", "change_confirmed"]
    assert verify(manager.audit.path)[0]


async def test_timeout_reverts(manager: ChangeManager, fw: FakeOPNsense) -> None:
    manager.timeout_s = 0.05
    before = fw.snapshot()
    result = await apply(manager, await plan_rules(manager, add()))
    assert result["status"] == "pending"
    await asyncio.sleep(0.3)
    change = manager.journal.get(result["id"])
    assert change is not None
    assert change.status == "reverted"
    assert fw.snapshot() == before
    assert fw.applies == 2  # apply + apply after revert
    assert manager.audit.tail(1)[0]["reason"] == "confirm timeout"


async def test_rollback_update_restores_only_our_fields(
    manager: ChangeManager, fw: FakeOPNsense
) -> None:
    uid = fw.add_rule(description="[mcp] old", destination_port="22", gateway="WAN_GW")
    before = fw.snapshot()
    op = RuleOp(op="update", uuid=uid, changes={"destination_port": "2222"})  # type: ignore[arg-type]
    result = await apply(manager, await plan_rules(manager, op))
    assert result["status"] == "pending", result
    assert fw.rules[uid]["destination_port"] == "2222"
    assert fw.rules[uid]["gateway"] == "WAN_GW"  # advanced field untouched

    rolled = await manager.rollback(result["id"], "stdio")
    assert rolled["status"] == "reverted"
    assert fw.snapshot() == before


async def test_rollback_delete_recreates_rule(manager: ChangeManager, fw: FakeOPNsense) -> None:
    uid = fw.add_rule(description="[mcp] temp", destination_port="80")
    original = dict(fw.rules[uid])
    result = await apply(manager, await plan_rules(manager, RuleOp(op="delete", uuid=uid)))
    assert result["status"] == "pending", result
    assert uid not in fw.rules

    rolled = await manager.rollback(result["id"], "stdio")
    assert rolled["status"] == "reverted"
    (recreated,) = fw.rules.values()
    for field in ("description", "destination_port", "action", "interface"):
        assert recreated[field] == original[field]
    assert rolled["objects"][0]["reverted_uuid"] in fw.rules


async def test_toggle_and_revert(manager: ChangeManager, fw: FakeOPNsense) -> None:
    uid = fw.add_rule(description="[mcp] t")
    op = RuleOp(op="toggle", uuid=uid, enabled=False)
    result = await apply(manager, await plan_rules(manager, op))
    assert fw.rules[uid]["enabled"] == "0"
    await manager.rollback(result["id"], "stdio")
    assert fw.rules[uid]["enabled"] == "1"


async def test_rollback_after_confirm(manager: ChangeManager, fw: FakeOPNsense) -> None:
    result = await apply(manager, await plan_rules(manager, add()))
    await manager.confirm(result["id"], "stdio")
    rolled = await manager.rollback(result["id"], "stdio")
    assert rolled["status"] == "reverted"
    assert not fw.rules


# ------------------------------------------------------------ safety paths


async def test_drift_since_plan_refused(manager: ChangeManager, fw: FakeOPNsense) -> None:
    uid = fw.add_rule(description="[mcp] x", destination_port="22")
    op = RuleOp(op="update", uuid=uid, changes={"destination_port": "23"})  # type: ignore[arg-type]
    plan_id = await plan_rules(manager, op)
    fw.rules[uid]["destination_port"] = "8022"  # someone else edits it
    result = await apply(manager, plan_id)
    assert result["status"] == "refused"
    assert "changed on the firewall since it was planned" in result["error"]
    assert fw.writes == []


async def test_verification_failure_reverts(manager: ChangeManager, fw: FakeOPNsense) -> None:
    def store_something_else(uid: str) -> None:
        fw.rules[uid]["destination_port"] = "2222"  # firewall kept a different value

    fw.after_add = store_something_else
    result = await apply(manager, await plan_rules(manager, add()))
    assert result["status"] == "failed", result
    assert "verification failed" in result["error"]
    assert "destination_port" in result["error"]
    assert not fw.rules


async def test_health_probe_failure_reverts(manager: ChangeManager, fw: FakeOPNsense) -> None:
    def lock_out(command: str, body: dict[str, Any]) -> None:
        if command == "apply" and fw.applies == 0:
            fw.healthy = False

    fw.on_write = lock_out
    result = await apply(manager, await plan_rules(manager, add()))
    assert result["status"] in ("failed", "revert_failed"), result
    assert "health probe failed" in result["error"]
    # the revert path still has the write API in this simulation
    assert not fw.rules


async def test_partial_failure_undoes_first_write(manager: ChangeManager, fw: FakeOPNsense) -> None:
    keep = fw.add_rule(description="[mcp] keep", destination_port="25")
    before = fw.snapshot()
    fw.fail_once = {"delRule"}
    result = await apply(manager, await plan_rules(manager, add(), RuleOp(op="delete", uuid=keep)))
    assert result["status"] == "failed", result
    assert fw.snapshot() == before


async def test_conflict_is_not_overwritten(manager: ChangeManager, fw: FakeOPNsense) -> None:
    result = await apply(manager, await plan_rules(manager, add()))
    (uid,) = fw.rules
    fw.rules[uid]["destination_port"] = "2200"  # a human edits our rule
    rolled = await manager.rollback(result["id"], "stdio")
    assert rolled["status"] == "conflict"
    assert fw.rules[uid]["destination_port"] == "2200"
    assert "changed by someone else" in rolled["error"]


async def test_one_open_change_at_a_time(manager: ChangeManager, fw: FakeOPNsense) -> None:
    first = await apply(manager, await plan_rules(manager, add()))
    second = await apply(manager, await plan_rules(manager, add(destination_port="23")))
    assert second["status"] == "refused"
    assert first["id"] in second["error"]


async def test_plan_rules_for_apply(manager: ChangeManager, fw: FakeOPNsense) -> None:
    plan_id = await plan_rules(manager, add())
    assert (await apply(manager, plan_id))["status"] == "pending"
    await manager.confirm((manager.journal.recent(1)[0]).id, "stdio")
    again = await apply(manager, plan_id)
    assert "already applied" in again["error"]
    assert "no plan" in (await apply(manager, "p_unknown"))["error"]
    denied = await manager.planner.plan_rules([add(interface="lan")], "stdio")
    assert "denied by policy" in (await apply(manager, denied.id))["error"]


async def test_rate_limit(manager: ChangeManager, fw: FakeOPNsense, policy: Policy) -> None:
    writes = policy.writes.model_copy(update={"max_changes_per_hour": 1})
    manager.policy = policy.model_copy(update={"writes": writes})
    first = await apply(manager, await plan_rules(manager, add()))
    await manager.confirm(first["id"], "stdio")
    second = await apply(manager, await plan_rules(manager, add(destination_port="23")))
    assert "rate limit" in second["error"]


async def test_policy_change_invalidates_plan(manager: ChangeManager, policy: Policy) -> None:
    plan_id = await plan_rules(manager, add())
    manager.policy = policy.model_copy(update={"sha256": "different"})
    assert "policy changed" in (await apply(manager, plan_id))["error"]


async def test_startup_recovery_reverts_open_changes(
    manager: ChangeManager, fw: FakeOPNsense
) -> None:
    result = await apply(manager, await plan_rules(manager, add()))
    await manager.aclose()  # simulate a crash: timer gone, journal still says pending
    reverted = await manager.revert_all_open("startup recovery")
    assert [r["id"] for r in reverted] == [result["id"]]
    assert reverted[0]["status"] == "reverted"
    assert not fw.rules


async def test_journal_survives_reopen(
    manager: ChangeManager, fw: FakeOPNsense, tmp_path: Path
) -> None:
    result = await apply(manager, await plan_rules(manager, add()))
    reopened = Journal(tmp_path / "journal.sqlite")
    change = reopened.get(result["id"])
    assert change is not None
    assert change.status == "pending"
    assert change.objects[0].uuid
    reopened.close()


# ------------------------------------------------------------------ aliases


async def test_alias_create_and_revert(manager: ChangeManager, fw: FakeOPNsense) -> None:
    op = AliasOp(op="create", name="mcp_scanners", type="host", entries=["192.168.50.7"])
    plan = await manager.planner.plan_aliases([op], "stdio")
    assert plan.allowed, plan.to_dict()["violations"]
    result = await apply(manager, plan.id)
    assert result["status"] == "pending", result
    alias = fw.alias_by_name("mcp_scanners")
    assert alias is not None
    assert alias["description"].startswith("[mcp]")
    assert fw.applies == 1  # alias reconfigure

    await manager.rollback(result["id"], "stdio")
    assert fw.alias_by_name("mcp_scanners") is None


async def test_alias_entries_revert(manager: ChangeManager, fw: FakeOPNsense) -> None:
    fw.add_alias("mcp_hosts", "host", ["192.168.50.5"], "[mcp] hosts")
    op = AliasOp(op="add_entries", name="mcp_hosts", entries=["192.168.50.9"])
    plan = await manager.planner.plan_aliases([op], "stdio")
    result = await apply(manager, plan.id)
    assert result["status"] == "pending", result
    assert fw.alias_by_name("mcp_hosts")["content"] == "192.168.50.5\n192.168.50.9"  # type: ignore[index]
    await manager.rollback(result["id"], "stdio")
    assert fw.alias_by_name("mcp_hosts")["content"] == "192.168.50.5"  # type: ignore[index]


# ------------------------------------------------------------ write client


@pytest.mark.parametrize(
    "path",
    [
        "/api/firewall/filter/addRule",
        "/api/firewall/filter/apply",
        "/api/firewall/filter/setRule/0b1c2d3e-1111-2222-3333-444455556666",
        "/api/firewall/filter/toggleRule/0b1c2d3e-1111-2222-3333-444455556666/0",
        "/api/firewall/alias/reconfigure",
    ],
)
def test_write_paths_allowed(path: str) -> None:
    assert check_write_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "/api/core/system/reboot",
        "/api/core/firmware/upgrade",
        "/api/core/service/restart/unbound",
        "/api/firewall/filter/savepoint",
        "/api/firewall/filter/setRule/not-a-uuid",
        "/api/firewall/filter/setRule/0b1c2d3e-1111-2222-3333-444455556666/../../x",
        "/api/firewall/filter/toggleRule/0b1c2d3e-1111-2222-3333-444455556666/2",
        "/api/firewall/filter/addRule?x=1",
        "/api/firewall/nat/addRule",
        "/api/auth/user/add",
    ],
)
def test_write_paths_refused(path: str) -> None:
    with pytest.raises(PathNotAllowed):
        check_write_path(path)


async def test_write_client_reports_validation_failure(
    write_client: WriteClient, api: respx.MockRouter
) -> None:
    from opnsense_guard.client import OPNsenseError

    api.post("/api/firewall/filter/addRule").respond(
        json={"result": "failed", "validations": {"rule.source_net": "invalid"}}
    )
    with pytest.raises(OPNsenseError, match="refused"):
        await write_client.post("/api/firewall/filter/addRule", {"rule": {}})


async def test_revert_unconfirmed_on_startup(
    tmp_path: Path, policy: Policy, fw: FakeOPNsense, monkeypatch: pytest.MonkeyPatch
) -> None:
    """main() runs this before serving: an unconfirmed change from a crashed run is undone."""
    from opnsense_guard.server import journal_path, revert_unconfirmed

    monkeypatch.setenv("OPNSENSE_GUARD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OPNSENSE_URL", "https://fw.test")
    monkeypatch.setenv("OPNSENSE_API_KEY", "r")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "r")
    monkeypatch.setenv("OPNSENSE_WRITE_API_KEY", "w")
    monkeypatch.setenv("OPNSENSE_WRITE_API_SECRET", "w")

    settings = ReadSettings(
        url="https://fw.test", api_key=SecretStr("r"), api_secret=SecretStr("r")
    )
    read, write = ReadClient(settings), WriteClient(settings)
    store = PlanStore()
    crashed = ChangeManager(
        policy,
        Planner(policy, lambda: read, store),
        store,
        Journal(journal_path()),
        AuditLog(tmp_path / "audit.jsonl"),
        lambda: read,
        lambda: write,
    )
    result = await apply(crashed, await plan_rules(crashed, add()))
    assert result["status"] == "pending"
    await crashed.aclose()
    crashed.journal.close()
    assert len(fw.rules) == 1

    count = await revert_unconfirmed(policy, AuditLog(tmp_path / "audit.jsonl"), "startup recovery")
    assert count == 1
    assert not fw.rules
    await read.aclose()
    await write.aclose()


async def test_sequence_sent_when_given_and_restored_on_undelete(
    manager: ChangeManager, fw: FakeOPNsense
) -> None:
    result = await apply(manager, await plan_rules(manager, add(sequence=50)))
    (uid,) = fw.rules
    assert fw.rules[uid]["sequence"] == "50"
    assert result["objects"][0]["planned"]["sequence"] == "50"
    await manager.confirm(result["id"], "stdio")

    deleted = await apply(manager, await plan_rules(manager, RuleOp(op="delete", uuid=uid)))
    await manager.rollback(deleted["id"], "stdio")
    (recreated,) = fw.rules.values()
    assert recreated["sequence"] == "50"  # back in the same place in the ruleset


async def test_auto_sequence_is_not_a_verification_failure(
    manager: ChangeManager, fw: FakeOPNsense
) -> None:
    result = await apply(manager, await plan_rules(manager, add()))
    assert result["status"] == "pending", result
    (rule,) = fw.rules.values()
    assert rule["sequence"]  # filled in by the firewall


async def test_failed_revert_is_reported_honestly(manager: ChangeManager, fw: FakeOPNsense) -> None:
    keep = fw.add_rule(description="[mcp] keep", destination_port="25")
    fw.fail = {"delRule"}  # the delete fails, and so does undoing the add
    result = await apply(manager, await plan_rules(manager, add(), RuleOp(op="delete", uuid=keep)))
    assert result["status"] == "revert_failed", result
    assert "could not be fully reverted" in result["note"]
    assert manager.audit.tail(1)[0]["event"] == "change_revert_problem"
