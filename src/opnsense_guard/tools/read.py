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
        """OPNsense firmware version, architecture, and pending update status."""
        return await safe("/api/core/firmware/status")

    @mcp.tool(annotations=READ_ONLY)
    async def system_information() -> Any:
        """Hostname, uptime, load, and general system information."""
        return await safe("/api/diagnostics/system/systemInformation")

    @mcp.tool(annotations=READ_ONLY)
    async def system_resources() -> Any:
        """Memory, swap, and disk utilisation of the firewall itself."""
        return await safe("/api/diagnostics/system/systemResources")

    @mcp.tool(annotations=READ_ONLY)
    async def service_list() -> Any:
        """All services OPNsense knows about and whether each is running."""
        return await safe("/api/core/service/search")

    @mcp.tool(annotations=READ_ONLY)
    async def posture_check() -> dict[str, Any]:
        """Health snapshot: firmware, services, IDS state.

        Flags security-relevant services that are installed but not running.
        """
        snapshot: dict[str, Any] = {
            "firmware": await safe("/api/core/firmware/status"),
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
    async def firewall_rules(search: str = "", limit: int = 200) -> Any:
        """The firewall filter ruleset.

        Args:
            search: optional text filter (interface, description, address).
            limit: maximum rules to return (1-1000).
        """
        params: dict[str, Any] = {"rowCount": _clamp(limit)}
        if search:
            params["searchPhrase"] = search
        return await safe("/api/firewall/filter/searchRule", params=params)

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
        return await safe("/api/diagnostics/firewall/queryStates", params=params)

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
        return await safe("/api/diagnostics/interface/getArp")

    @mcp.tool(annotations=READ_ONLY)
    async def routing_table() -> Any:
        """The firewall's active routing table."""
        return await safe("/api/diagnostics/interface/getRoutes")

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
