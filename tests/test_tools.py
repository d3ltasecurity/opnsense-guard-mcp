import respx
from mcp.server import MCPServer

from conftest import call

UUID = "0b1c2d3e-1111-2222-3333-444455556666"


async def test_all_tools_are_read_only(server: MCPServer) -> None:
    tools = await server.list_tools()
    assert len(tools) == 21  # 19 read + policy_show + security_audit
    for tool in tools:
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name


async def test_system_status(server: MCPServer, api: respx.MockRouter) -> None:
    api.get("/api/core/firmware/status").respond(json={"product_version": "26.7.4"})
    assert await call(server, "system_status") == {"product_version": "26.7.4"}


async def test_errors_come_back_as_data(server: MCPServer, api: respx.MockRouter) -> None:
    api.get("/api/core/firmware/status").respond(403)
    result = await call(server, "system_status")
    assert "403" in result["error"]


async def test_firewall_rules_params_and_clamp(server: MCPServer, api: respx.MockRouter) -> None:
    route = api.get("/api/firewall/filter/searchRule").respond(json={"rows": []})
    await call(server, "firewall_rules", {"search": "dmz", "limit": 999999})
    params = route.calls.last.request.url.params
    assert params["rowCount"] == "1000"
    assert params["searchPhrase"] == "dmz"


async def test_firewall_rules_are_one_line_each(server: MCPServer, api: respx.MockRouter) -> None:
    row = {
        "uuid": UUID,
        "sequence": "10",
        "enabled": "1",
        "action": "block",
        "interface": "opt1",
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "TCP",
        "source_net": "lan",
        "source_not": "1",
        "destination_net": "any",
        "destination_port": "22",
        "description": "[mcp] test",
        "gateway": "x" * 2000,
    }
    api.get("/api/firewall/filter/searchRule").respond(json={"rows": [row], "total": 38})
    result = await call(server, "firewall_rules")
    assert result["total"] == 38
    assert result["shown"] == 1
    assert result["rows"] == [
        {
            "uuid": UUID,
            "rule": "#10 [opt1] block in inet TCP from !lan to any port 22 '[mcp] test'",
        }
    ]
    auto = {
        "uuid": "02f4bab031b57d1e30553ce08e0ec131",
        "action": "block",
        "direction": "in",
        "ipprotocol": "inet46",
        "log": "True",
        "quick": "False",
        "description": "Default deny",
        "is_automatic": "True",
    }
    api.get("/api/firewall/filter/searchRule").respond(json={"rows": [auto]})
    line = (await call(server, "firewall_rules"))["rows"][0]["rule"]
    assert line == (
        "[auto] [any] block in inet46 any from any to any [log] 'Default deny'"
        " (not quick: a later match wins)"
    )
    api.get("/api/firewall/filter/searchRule").respond(json={"rows": [row]})
    full = await call(server, "firewall_rules", {"detail": True})
    assert full["rowCount"] == 1
    assert full["rows"][0]["gateway"] == "x" * 2000


async def test_firewall_rules_filters_and_limits_itself(
    server: MCPServer, api: respx.MockRouter
) -> None:
    # Real 26.7.4 ignores rowCount/searchPhrase on GET searchRule.
    rows = [{"uuid": str(i), "description": f"rule {i}", "action": "pass"} for i in range(10)]
    rows[7]["description"] = "Kali DMZ"
    api.get("/api/firewall/filter/searchRule").respond(json={"rows": rows, "total": 10})
    found = await call(server, "firewall_rules", {"search": "kali"})
    assert [r["uuid"] for r in found["rows"]] == ["7"]
    first = await call(server, "firewall_rules", {"limit": 3})
    assert first["total"] == 10
    assert first["shown"] == 3


async def test_firewall_rule_get(server: MCPServer, api: respx.MockRouter) -> None:
    api.get(f"/api/firewall/filter/getRule/{UUID}").respond(json={"rule": {"action": "pass"}})
    assert await call(server, "firewall_rule_get", {"uuid": UUID}) == {"rule": {"action": "pass"}}


async def test_firewall_rule_get_rejects_bad_uuid(server: MCPServer, api: respx.MockRouter) -> None:
    result = await call(server, "firewall_rule_get", {"uuid": "../../core/system/reboot"})
    assert "error" in result
    assert not api.calls


async def test_raw_get_cannot_mutate(server: MCPServer, api: respx.MockRouter) -> None:
    for path in ("/api/core/system/reboot", "/api/firewall/filter/apply", "/api/auth/user/search"):
        result = await call(server, "raw_get", {"path": path})
        assert "refused" in result["error"]
    assert not api.calls


async def test_posture_flags_stopped_services(server: MCPServer, api: respx.MockRouter) -> None:
    api.get("/api/diagnostics/system/system_information").respond(json={})
    api.get("/api/ids/service/status").respond(json={"status": "stopped"})
    api.get("/api/core/service/search").respond(
        json={
            "rows": [
                {"name": "suricata", "description": "IDS", "running": 0},
                {"name": "unbound", "description": "DNS", "running": 1},
            ]
        }
    )
    result = await call(server, "posture_check")
    assert "suricata is installed but NOT running" in result["concerns"]
    assert "Suricata/IDS status is 'stopped'" in result["concerns"]
    assert not any("unbound" in c for c in result["concerns"])


async def test_suricata_alert_status(server: MCPServer, api: respx.MockRouter) -> None:
    api.get("/api/ids/service/getAlertLogs").respond(
        json=[{"filename": "eve.json", "size": 2048, "modified": "2026-10-25 10:00"}]
    )
    result = await call(server, "suricata_alert_status")
    assert "2048 bytes" in result["assessment"]


async def test_dhcp_leases_picks_active_backend(server: MCPServer, api: respx.MockRouter) -> None:
    api.get("/api/kea/leases4/search").respond(json={"rows": []})
    api.get("/api/dhcpv4/leases/searchLease").respond(404)
    api.get("/api/dnsmasq/leases/search").respond(json={"rows": [{"address": "10.0.0.5"}]})
    result = await call(server, "dhcp_leases")
    assert result["active_backend"] == "dnsmasq"
    assert result["dnsmasq"]["count"] == 1
    assert "404" in result["isc"]["error"]
