from pathlib import Path
from typing import Any

import pytest
import respx
from pydantic import ValidationError

from opnsense_guard.client import ReadClient
from opnsense_guard.planner import AliasOp, Planner, PlanStore, RuleOp, flatten, normalise_rule
from opnsense_guard.policy import Policy, load_policy

ROOT = Path(__file__).resolve().parent.parent
TAGGED = "0b1c2d3e-1111-2222-3333-444455556666"
UNTAGGED = "0b1c2d3e-1111-2222-3333-777788889999"
PROTECTED_IFACE_RULE = "0b1c2d3e-1111-2222-3333-aaaabbbbcccc"


def options(selected: str, *others: str) -> dict[str, Any]:
    """The {key: {value, selected}} shape OPNsense uses for option fields."""
    out = {selected: {"value": selected.title(), "selected": 1}}
    out.update({o: {"value": o.title(), "selected": 0} for o in others})
    return out


def api_rule(description: str, interface: str = "opt1", action: str = "block") -> dict[str, Any]:
    return {
        "rule": {
            "enabled": "1",
            "action": options(action, *({"pass", "block", "reject"} - {action})),
            "interface": options(interface, "lan", "wan"),
            "direction": options("in", "out"),
            "ipprotocol": options("inet", "inet6"),
            "protocol": options("TCP", "any", "UDP"),
            "source_net": "192.168.50.5",
            "source_port": "",
            "destination_net": "any",
            "destination_port": "22",
            "log": "1",
            "description": description,
        }
    }


@pytest.fixture
def policy() -> Policy:
    return load_policy(ROOT / "policy.example.yaml")


@pytest.fixture
def planner(policy: Policy, client: ReadClient) -> Planner:
    return Planner(policy, lambda: client, PlanStore())


@pytest.fixture
def rules_api(api: respx.MockRouter) -> respx.MockRouter:
    base = "/api/firewall/filter/getRule/"
    api.get(base + TAGGED).respond(json=api_rule("[mcp] block ssh"))
    api.get(base + UNTAGGED).respond(json=api_rule("hand-made rule"))
    api.get(base + PROTECTED_IFACE_RULE).respond(
        json=api_rule("[mcp] on services", interface="opt2", action="pass")
    )
    return api


def add(**rule: Any) -> RuleOp:
    base = {"action": "block", "interface": "opt1", "source_net": "192.168.50.0/24"}
    return RuleOp(op="add", rule={**base, **rule})  # type: ignore[arg-type]


async def plan(planner: Planner, *ops: RuleOp) -> dict[str, Any]:
    return (await planner.plan_rules(list(ops), "stdio")).to_dict()


# ---------------------------------------------------------------- helpers


def test_flatten_option_fields() -> None:
    assert flatten(options("opt1", "lan")) == "opt1"
    assert flatten({"a": {"selected": 1}, "b": {"selected": "1"}, "c": {"selected": 0}}) == "a,b"
    assert flatten(True) == "1"
    assert flatten(None) == ""
    assert normalise_rule(api_rule("x")["rule"])["action"] == "block"


def test_op_shape_validation() -> None:
    with pytest.raises(ValidationError):
        RuleOp(op="add")
    with pytest.raises(ValidationError):
        RuleOp(op="delete", uuid="../../x")
    with pytest.raises(ValidationError):
        RuleOp(op="toggle", uuid=TAGGED)
    with pytest.raises(ValidationError):
        RuleOp.model_validate(
            {"op": "add", "rule": {"action": "block", "interface": "opt1", "x": 1}}
        )
    with pytest.raises(ValidationError):
        AliasOp(op="create", name="mcp_x")  # no type
    with pytest.raises(ValidationError):
        AliasOp(op="delete", name="bad name!")


# ------------------------------------------------------------------ rules


async def test_add_allowed_and_tagged(planner: Planner) -> None:
    result = await plan(planner, add(destination_port="22", description="block ssh"))
    assert result["status"] == "allowed", result["violations"]
    after = result["objects"][0]["after"]
    assert after["description"] == "[mcp] block ssh"
    assert after["log"] == "1"
    assert result["diff"][0].startswith("+ [opt1] block in")
    assert "Nothing was changed" in result["note"]


async def test_read_only_policy_denies(client: ReadClient) -> None:
    planner = Planner(Policy(), lambda: client, PlanStore())
    result = await plan(planner, add())
    assert result["status"] == "denied"
    assert any("read_only" in v for v in result["violations"])


@pytest.mark.parametrize(
    ("rule", "fragment"),
    [
        ({"action": "pass", "source_net": "any", "destination_net": "any"}, "any -> any"),
        ({"interface": "lan"}, "interface 'lan'"),
        ({"interface": "opt1,opt2"}, "floating"),
        ({"source_net": "10.9.9.0/24"}, "outside allow_networks"),
        ({"destination_net": "evil_alias"}, "not an allowed interface token"),
        ({"destination_net": "lanip"}, "not an allowed interface token"),
        ({"log": False}, "logging"),
        ({"destination_port": "70000"}, "out of range"),
        ({"destination_port": "ssh"}, "must be a port"),
        ({"direction": "out"}, "direction 'out'"),
    ],
)
async def test_add_denied(planner: Planner, rule: dict[str, Any], fragment: str) -> None:
    result = await plan(planner, add(**rule))
    assert result["status"] == "denied"
    assert any(fragment in v for v in result["violations"]), result["violations"]


async def test_allowed_net_forms(planner: Planner) -> None:
    result = await plan(
        planner,
        add(source_net="opt1", destination_net="(self)"),
        add(source_net="192.168.50.7,mcp_hosts", destination_net="opt1ip"),
    )
    assert result["status"] == "allowed", result["violations"]


async def test_anti_lockout_block_matching_mcp_host(planner: Planner) -> None:
    for source in ("any", "192.168.60.0/24", "192.168.60.10", "opt2"):
        result = await plan(planner, add(source_net=source))
        assert any("anti_lockout" in v or "own address" in v for v in result["violations"]), source


async def test_anti_lockout_protected_interface(planner: Planner, rules_api: Any) -> None:
    blocked = await plan(planner, add(interface="opt2", source_net="192.168.50.0/24"))
    assert any("protected_interfaces" in v for v in blocked["violations"])
    passing = await plan(planner, add(interface="opt2", action="pass", destination_port="443"))
    assert passing["status"] == "allowed", passing["violations"]
    delete = await plan(planner, RuleOp(op="delete", uuid=PROTECTED_IFACE_RULE))
    assert any("protected_interfaces" in v for v in delete["violations"])


async def test_update_own_rule_shows_diff(planner: Planner, rules_api: Any) -> None:
    op = RuleOp(op="update", uuid=TAGGED, changes={"destination_port": "2222"})  # type: ignore[arg-type]
    result = await plan(planner, op)
    assert result["status"] == "allowed", result["violations"]
    assert "    destination_port: '22' -> '2222'" in result["diff"]
    assert result["objects"][0]["before"]["destination_port"] == "22"


async def test_only_modify_own(planner: Planner, rules_api: Any) -> None:
    for op in (
        RuleOp(op="delete", uuid=UNTAGGED),
        RuleOp(op="toggle", uuid=UNTAGGED, enabled=False),
    ):
        result = await plan(planner, op)
        assert any("only_modify_own" in v for v in result["violations"])


async def test_toggle_own_rule(planner: Planner, rules_api: Any) -> None:
    result = await plan(planner, RuleOp(op="toggle", uuid=TAGGED, enabled=False))
    assert result["status"] == "allowed", result["violations"]
    assert "    enabled: '1' -> '0'" in result["diff"]


async def test_protect_uuids(client: ReadClient, policy: Policy, rules_api: Any) -> None:
    rules = policy.writes.rules.model_copy(update={"protect_uuids": [TAGGED]})
    writes = policy.writes.model_copy(update={"rules": rules})
    planner = Planner(policy.model_copy(update={"writes": writes}), lambda: client, PlanStore())
    result = await plan(planner, RuleOp(op="delete", uuid=TAGGED))
    assert any("protect_uuids" in v for v in result["violations"])


async def test_missing_rule(planner: Planner, api: respx.MockRouter) -> None:
    api.get(f"/api/firewall/filter/getRule/{TAGGED}").respond(404)
    result = await plan(planner, RuleOp(op="delete", uuid=TAGGED))
    assert any("could not read rule" in v for v in result["violations"])


async def test_too_many_objects(planner: Planner) -> None:
    result = await plan(planner, *[add() for _ in range(6)])
    assert any("max_objects_per_change" in v for v in result["violations"])


async def test_plan_is_stored(planner: Planner) -> None:
    created = await planner.plan_rules([add()], "token:laptop")
    stored = planner.store.get(created.id)
    assert stored is not None
    assert stored.actor == "token:laptop"


async def test_planning_never_writes(planner: Planner, rules_api: respx.MockRouter) -> None:
    await plan(planner, add(), RuleOp(op="delete", uuid=TAGGED))
    assert all(call.request.method == "GET" for call in rules_api.calls)


# ---------------------------------------------------------------- aliases


@pytest.fixture
def alias_api(api: respx.MockRouter) -> respx.MockRouter:
    api.get("/api/firewall/alias/getAliasUUID/mcp_new").respond(json={})
    api.get("/api/firewall/alias/getAliasUUID/mcp_hosts").respond(json={"uuid": TAGGED})
    api.get(f"/api/firewall/alias/getItem/{TAGGED}").respond(
        json={
            "alias": {
                "type": options("host", "network", "port"),
                "content": {
                    "192.168.50.5": {"value": "192.168.50.5", "selected": 1},
                    "192.168.50.6": {"value": "192.168.50.6", "selected": 1},
                },
                "description": "[mcp] hosts",
            }
        }
    )
    return api


async def aplan(planner: Planner, *ops: AliasOp) -> dict[str, Any]:
    return (await planner.plan_aliases(list(ops), "stdio")).to_dict()


async def test_alias_create(planner: Planner, alias_api: Any) -> None:
    result = await aplan(
        planner, AliasOp(op="create", name="mcp_new", type="network", entries=["192.168.50.0/28"])
    )
    assert result["status"] == "allowed", result["violations"]
    assert result["objects"][0]["after"]["description"].startswith("[mcp]")


@pytest.mark.parametrize(
    ("op", "fragment"),
    [
        (AliasOp(op="create", name="other", type="host", entries=["192.168.50.1"]), "must start"),
        (AliasOp(op="create", name="mcp_new", type="host", entries=["10.1.1.1"]), "outside"),
        (AliasOp(op="create", name="mcp_new", type="host", entries=["evil.example"]), "hostnames"),
        (
            AliasOp(op="create", name="mcp_new", type="host", entries=["192.168.60.10"]),
            "own address",
        ),
        (AliasOp(op="create", name="mcp_new", type="host", entries=["192.168.50.0/24"]), "single"),
        (AliasOp(op="create", name="mcp_new", type="port", entries=["99999"]), "out of range"),
        (AliasOp(op="create", name="mcp_hosts", type="host", entries=[]), "already exists"),
    ],
)
async def test_alias_denied(planner: Planner, alias_api: Any, op: AliasOp, fragment: str) -> None:
    result = await aplan(planner, op)
    assert result["status"] == "denied"
    assert any(fragment in v for v in result["violations"]), result["violations"]


async def test_alias_add_and_remove_entries(planner: Planner, alias_api: Any) -> None:
    added = await aplan(
        planner, AliasOp(op="add_entries", name="mcp_hosts", entries=["192.168.50.7"])
    )
    assert added["status"] == "allowed", added["violations"]
    assert added["objects"][0]["after"]["entries"] == "192.168.50.5,192.168.50.6,192.168.50.7"
    removed = await aplan(
        planner, AliasOp(op="remove_entries", name="mcp_hosts", entries=["192.168.50.5"])
    )
    assert removed["objects"][0]["after"]["entries"] == "192.168.50.6"


async def test_alias_delete_missing(planner: Planner, alias_api: Any) -> None:
    result = await aplan(planner, AliasOp(op="delete", name="mcp_new"))
    assert any("not found" in v for v in result["violations"])
