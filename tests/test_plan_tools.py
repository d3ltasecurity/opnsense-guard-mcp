from pathlib import Path

import pytest
import respx
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from conftest import call
from opnsense_guard.audit import AuditLog, verify
from opnsense_guard.client import ReadClient
from opnsense_guard.policy import load_policy
from opnsense_guard.server import build_server

ROOT = Path(__file__).resolve().parent.parent
WRITE_TOOLS = {"rule_plan", "alias_plan", "plan_get", "audit_tail"}
ADD = {
    "op": "add",
    "rule": {
        "action": "block",
        "interface": "opt1",
        "source_net": "192.168.50.0/24",
        "destination_port": "22",
    },
}


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def write_server(client: ReadClient, audit: AuditLog) -> MCPServer:
    return build_server(lambda: client, load_policy(ROOT / "policy.example.yaml"), audit)


async def test_read_only_server_has_no_plan_tools(server: MCPServer) -> None:
    names = {t.name for t in await server.list_tools()}
    assert not names & WRITE_TOOLS
    assert {"policy_show", "security_audit"} <= names


async def test_write_server_tools_are_all_non_destructive(write_server: MCPServer) -> None:
    tools = await write_server.list_tools()
    assert {t.name for t in tools} >= WRITE_TOOLS
    for tool in tools:
        assert tool.annotations is not None
        assert tool.annotations.destructive_hint is False, tool.name


async def test_rule_plan_is_audited(
    write_server: MCPServer, audit: AuditLog, api: respx.MockRouter
) -> None:
    result = await call(write_server, "rule_plan", {"operations": [ADD]})
    assert result["status"] == "allowed", result["violations"]
    assert not api.calls  # an add needs no reads, and planning never writes

    events = audit.tail(5)
    assert events[-1]["event"] == "plan_created"
    assert events[-1]["plan_id"] == result["plan_id"]
    assert events[-1]["actor"] == "stdio"
    assert events[-1]["status"] == "allowed"
    assert verify(audit.path)[0]


async def test_denied_plan_is_audited_too(write_server: MCPServer, audit: AuditLog) -> None:
    bad = {"op": "add", "rule": {**ADD["rule"], "interface": "lan"}}  # type: ignore[dict-item]
    result = await call(write_server, "rule_plan", {"operations": [bad]})
    assert result["status"] == "denied"
    assert audit.tail(1)[0]["status"] == "denied"


async def test_bad_operation_shape_is_an_error(write_server: MCPServer) -> None:
    with pytest.raises(ToolError, match="validation error"):
        await write_server.call_tool("rule_plan", {"operations": [{"op": "explode"}]})


async def test_plan_get_and_audit_tail(write_server: MCPServer) -> None:
    created = await call(write_server, "rule_plan", {"operations": [ADD]})
    fetched = await call(write_server, "plan_get", {"plan_id": created["plan_id"]})
    assert fetched["diff"] == created["diff"]
    assert "error" in await call(write_server, "plan_get", {"plan_id": "p_nope"})
    response = await write_server.call_tool("audit_tail", {"limit": 5})
    assert response.structured_content is not None
    events = response.structured_content["result"]
    assert events[-1]["event"] == "plan_created"


async def test_policy_show(write_server: MCPServer) -> None:
    summary = await call(write_server, "policy_show")
    assert summary["mode"] == "write"
    assert summary["writes"]["rules"]["interfaces"] == ["opt1", "opt2"]
    assert len(summary["policy_sha256"]) == 64


async def test_security_audit(server: MCPServer, api: respx.MockRouter) -> None:
    api.get("/api/firewall/filter/searchRule").respond(
        json={
            "rows": [
                {
                    "uuid": "a",
                    "enabled": "1",
                    "action": "pass",
                    "interface": "lan",
                    "direction": "in",
                    "source_net": "any",
                    "destination_net": "any",
                    "log": "0",
                    "description": "allow all",
                },
                {
                    "uuid": "b",
                    "enabled": "1",
                    "action": "pass",
                    "interface": "wan",
                    "direction": "in",
                    "source_net": "any",
                    "destination_net": "192.168.1.5",
                    "log": "1",
                    "description": "[mcp] web",
                },
                {"uuid": "c", "enabled": "0", "action": "pass", "description": "old"},
                {
                    # automatic rules come back like this in 26.7: 32-hex id,
                    # interface by description, empty nets meaning "any"
                    "uuid": "fae559338f65e11c53669fc3642c93c2",
                    "enabled": "1",
                    "action": "pass",
                    "direction": "out",
                    "source_net": "",
                    "destination_net": "",
                    "log": True,
                    "description": "let out anything from firewall host itself",
                    "legacy": True,
                    "is_automatic": True,
                },
                {
                    "uuid": "d",
                    "enabled": "1",
                    "action": "pass",
                    "interface": "opt1",
                    "direction": "in",
                    "source_net": "",
                    "destination_net": "",
                    "log": "1",
                    "description": "empty nets mean any",
                },
            ]
        }
    )
    api.get("/api/ids/service/status").respond(json={"status": "stopped"})
    result = await call(server, "security_audit")
    issues = {(f["severity"], f["issue"]) for f in result["rules"]["findings"]}
    assert ("high", "any -> any pass rule") in issues
    assert ("medium", "inbound pass on WAN") in issues
    assert ("low", "pass rule without logging") in issues
    assert result["rules"]["counts"] == {
        "total": 5,
        "automatic": 1,
        "disabled": 1,
        "tagged_by_this_server": 1,
    }
    flagged = [f["rule"] for f in result["rules"]["findings"]]
    assert not any("let out anything" in ref for ref in flagged)
    assert any("empty nets mean any" in ref for ref in flagged)
    assert result["ids"]["finding"] == "IDS/IPS is not running"


def test_actor_from_http_token_state() -> None:
    from types import SimpleNamespace

    from opnsense_guard.tools.plan import actor_of

    request = SimpleNamespace(scope={"state": {"token_name": "laptop", "token_scope": "read"}})
    ctx = SimpleNamespace(request_context=SimpleNamespace(request=request))
    assert actor_of(ctx) == "token:laptop"  # type: ignore[arg-type]
    stdio = SimpleNamespace(request_context=SimpleNamespace(request=None))
    assert actor_of(stdio) == "stdio"  # type: ignore[arg-type]
    assert actor_of(None) == "stdio"
