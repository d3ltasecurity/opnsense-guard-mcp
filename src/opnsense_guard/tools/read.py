"""Read-only MCP tools.

Every tool goes through ReadClient (GET-only, allowlisted). Errors come back
to the model as ``{"error": ..., "path": ...}`` instead of raising, so one
missing endpoint does not break a whole conversation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from opnsense_guard.client import OPNsenseError, ReadClient
from opnsense_guard.planner import describe_rule, flatten, normalise_rule

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

MAX_LIMIT = 1000

# Services whose absence matters for security posture.
WATCHED_SERVICES = ("suricata", "ids", "zenarmor", "sensei", "syslog", "unbound", "dnsmasq")

DHCP_BACKENDS = {
    "kea": "/api/kea/leases4/search",
    "isc": "/api/dhcpv4/leases/searchLease",
    "dnsmasq": "/api/dnsmasq/leases/search",
}


def _clamp(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


def _compact_rule(row: dict[str, Any]) -> dict[str, str]:
    """One line per rule. A full row is ~1.5 KB; 40 of them swamp a chat."""
    # Automatic rules say True/False where user rules say 1/0, and leave
    # fields empty that mean "any".
    r = {k: {"True": "1", "False": "0"}.get(v, v) for k, v in normalise_rule(row).items()}
    for field in ("interface", "protocol", "source_net", "destination_net"):
        r[field] = r[field] or "any"
    # Show negation, or "from !lan" would read as "from lan".
    for flag, field in (
        ("interfacenot", "interface"),
        ("source_not", "source_net"),
        ("destination_not", "destination_net"),
    ):
        if r[flag] == "1":
            r[field] = "!" + r[field]
    text = describe_rule(r).removeprefix("#(auto) ")  # no sequence: built-in order
    if r["quick"] == "0":
        text += " (not quick: a later match wins)"
    if flatten(row.get("is_automatic", "")) in ("1", "True"):
        text = "[auto] " + text
    return {"uuid": str(row.get("uuid", "")), "rule": text}


def register_read_tools(mcp: MCPServer, get_client: Callable[[], ReadClient]) -> None:
    """Attach all read tools to ``mcp``. ``get_client`` is called lazily."""

    async def safe(path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            return await get_client().get(path, params=params)
        except OPNsenseError as exc:
            return {"error": str(exc), "path": path}

    # ---------------------------------------------------------------- system

    @mcp.tool(annotations=READ_ONLY)
    async def system_status() -> Any:
        """OPNsense firmware version and pending updates (needs the System: Firmware privilege)."""
        return await safe("/api/core/firmware/status")

    @mcp.tool(annotations=READ_ONLY)
    async def system_information() -> Any:
        """Hostname, uptime, load, and general system information."""
        return await safe("/api/diagnostics/system/system_information")

    @mcp.tool(annotations=READ_ONLY)
    async def system_resources() -> Any:
        """Memory, swap, and disk utilisation of the firewall itself."""
        return await safe("/api/diagnostics/system/system_resources")

    @mcp.tool(annotations=READ_ONLY)
    async def service_list() -> Any:
        """All services OPNsense knows about and whether each is running."""
        return await safe("/api/core/service/search")

    @mcp.tool(annotations=READ_ONLY)
    async def posture_check() -> dict[str, Any]:
        """Health snapshot: system, services, IDS state.

        Flags security-relevant services that are installed but not running.
        """
        snapshot: dict[str, Any] = {
            "system": await safe("/api/diagnostics/system/system_information"),
            "ids_service": await safe("/api/ids/service/status"),
        }
        services = await safe("/api/core/service/search")
        snapshot["services"] = services

        concerns: list[str] = []
        rows = services.get("rows") if isinstance(services, dict) else None
        if isinstance(rows, list):
            for row in rows:
                name = str(row.get("name", "")).lower()
                description = str(row.get("description", "")).lower()
                watched = any(w in name or w in description for w in WATCHED_SERVICES)
                if watched and row.get("running") in (0, "0", False):
                    concerns.append(f"{row.get('name')} is installed but NOT running")

        ids_state = snapshot["ids_service"]
        if isinstance(ids_state, dict) and ids_state.get("status") not in (None, "running"):
            concerns.append(f"Suricata/IDS status is '{ids_state.get('status')}'")

        snapshot["concerns"] = concerns or ["no obvious service-level gaps detected"]
        return snapshot

    # ------------------------------------------------------ intrusion detection

    @mcp.tool(annotations=READ_ONLY)
    async def suricata_status() -> Any:
        """Whether the Suricata IDS/IPS service is running, stopped, or disabled."""
        return await safe("/api/ids/service/status")

    @mcp.tool(annotations=READ_ONLY)
    async def suricata_settings() -> Any:
        """Suricata configuration: enabled, IPS mode, interfaces, active rulesets."""
        return await safe("/api/ids/settings/get")

    @mcp.tool(annotations=READ_ONLY)
    async def suricata_alert_status() -> dict[str, Any]:
        """Whether Suricata is producing alerts, from its eve.json file metadata.

        OPNsense only serves alert *rows* over POST (queryAlerts), which a
        read-only server must not call. This reports liveness instead: the
        log file's size and last-modified time. Query alerts in your SIEM.
        """
        logs = await safe("/api/ids/service/getAlertLogs")

        assessment = "could not read alert log listing"
        if isinstance(logs, list) and logs:
            eve = next((f for f in logs if f.get("filename") == "eve.json"), logs[0])
            size = eve.get("size", 0)
            modified = eve.get("modified", "unknown")
            if isinstance(size, int | float) and size > 0:
                assessment = (
                    f"eve.json is {size} bytes, last written {modified}. The IDS is logging."
                )
            else:
                assessment = (
                    f"eve.json exists but is empty (last modified {modified}). "
                    "Suricata is running but has logged no alerts yet."
                )
        elif isinstance(logs, list):
            assessment = "no alert log files exist yet"

        return {"alert_logs": logs, "assessment": assessment}

    # ------------------------------------------------------------ firewall

    @mcp.tool(annotations=READ_ONLY)
    async def firewall_rules(search: str = "", limit: int = 50, detail: bool = False) -> Any:
        """The firewall filter ruleset, one line per rule.

        Use firewall_rule_get for every field of one rule.

        Args:
            search: optional text filter (interface, description, address).
            limit: maximum rules to return (1-1000).
            detail: return the full OPNsense rows instead of one-line summaries.
        """
        params: dict[str, Any] = {"rowCount": _clamp(limit)}
        if search:
            params["searchPhrase"] = search
        result = await safe("/api/firewall/filter/searchRule", params=params)
        if detail or not isinstance(result, dict) or not isinstance(result.get("rows"), list):
            return result
        rows = result["rows"]
        return {
            "total": result.get("total", len(rows)),
            "shown": len(rows),
            "rows": [_compact_rule(row) for row in rows if isinstance(row, dict)],
        }

    @mcp.tool(annotations=READ_ONLY)
    async def firewall_rule_get(uuid: str) -> Any:
        """One filter rule by UUID, with all fields.

        Args:
            uuid: rule UUID as shown by firewall_rules.
        """
        if not UUID_RE.match(uuid):
            return {"error": "uuid must be a UUID like 0b1c2d3e-...", "uuid": uuid}
        return await safe(f"/api/firewall/filter/getRule/{uuid}")

    @mcp.tool(annotations=READ_ONLY)
    async def firewall_aliases(search: str = "", limit: int = 200) -> Any:
        """Firewall aliases and their contents.

        Args:
            search: optional text filter on alias name or description.
            limit: maximum aliases to return (1-1000).
        """
        params: dict[str, Any] = {"rowCount": _clamp(limit)}
        if search:
            params["searchPhrase"] = search
        return await safe("/api/firewall/alias/searchItem", params=params)

    # ------------------------------------------------------ traffic and logs

    @mcp.tool(annotations=READ_ONLY)
    async def firewall_log(limit: int = 100, search: str = "") -> Any:
        """Recent firewall log entries (pass/block decisions).

        Args:
            limit: number of log lines to return (1-1000).
            search: optional filter phrase (IP, port, interface, action).
        """
        params: dict[str, Any] = {"limit": _clamp(limit)}
        if search:
            params["searchPhrase"] = search
        return await safe("/api/diagnostics/firewall/log", params=params)

    @mcp.tool(annotations=READ_ONLY)
    async def firewall_states(limit: int = 100, search: str = "") -> Any:
        """Active connection state table.

        Args:
            limit: number of states to return (1-1000).
            search: optional filter on address or port.
        """
        params: dict[str, Any] = {"rowCount": _clamp(limit)}
        if search:
            params["searchPhrase"] = search
        return await safe("/api/diagnostics/firewall/query_states", params=params)

    @mcp.tool(annotations=READ_ONLY)
    async def system_log(limit: int = 100) -> Any:
        """Recent entries from the OPNsense system log.

        Args:
            limit: number of lines to return (1-1000).
        """
        return await safe("/api/diagnostics/log/core/system", params={"limit": _clamp(limit)})

    # ------------------------------------------------------------- network

    @mcp.tool(annotations=READ_ONLY)
    async def interfaces() -> Any:
        """All network interfaces with status, addresses, and link state."""
        return await safe("/api/interfaces/overview/interfacesInfo")

    @mcp.tool(annotations=READ_ONLY)
    async def arp_table() -> Any:
        """ARP table: IP to MAC mappings currently known to the firewall."""
        return await safe("/api/diagnostics/interface/get_arp")

    @mcp.tool(annotations=READ_ONLY)
    async def routing_table() -> Any:
        """The firewall's active routing table."""
        return await safe("/api/diagnostics/interface/get_routes")

    @mcp.tool(annotations=READ_ONLY)
    async def dhcp_leases() -> dict[str, Any]:
        """Current DHCP leases across all backends (Kea, ISC dhcpd, dnsmasq).

        Queries all three and reports which backend actually holds leases.
        """
        out: dict[str, Any] = {}
        active_backend = None
        for name, path in DHCP_BACKENDS.items():
            result = await safe(path, params={"rowCount": 500})
            rows = result.get("rows") if isinstance(result, dict) else None
            count = len(rows) if isinstance(rows, list) else None
            out[name] = {
                "path": path,
                "count": count,
                "error": result.get("error") if isinstance(result, dict) else None,
                "rows": rows if count else None,
            }
            if count:
                active_backend = name
        out["active_backend"] = active_backend or "none returned leases"
        return out

    # --------------------------------------------------------- escape hatch

    @mcp.tool(annotations=READ_ONLY)
    async def raw_get(path: str) -> Any:
        """GET any allowlisted OPNsense API path.

        The same read-only rules apply (prefix allowlist, verb denylist, no
        traversal), so this cannot change firewall state.

        Args:
            path: API path beginning with /api/, e.g. /api/core/firmware/info
        """
        return await safe(path)
