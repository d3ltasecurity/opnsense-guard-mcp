"""Read-only OPNsense API client.

Design rules (do not relax without a security review):

1. GET only. This class has no method that sends POST/PUT/DELETE.
2. Paths are normalised and rejected if they contain anything that could
   smuggle a different endpoint past the checks (``..``, ``%``, ``?``, ``#``,
   backslashes, empty segments, non-ASCII).
3. The command segment is checked against a verb denylist *before* the
   allowlist. Some OPNsense endpoints perform actions even over GET, so the
   prefix allowlist alone is not enough.
4. Redirects are never followed (a redirect usually means a login page).

The module knows nothing about MCP, so other tooling can import it directly.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from opnsense_guard import __version__
from opnsense_guard.config import ReadSettings


class OPNsenseError(RuntimeError):
    """Any failure talking to the OPNsense API."""


class PathNotAllowed(OPNsenseError):
    """The requested path failed the read policy."""


# Path prefixes the read-only API user is expected to have privileges for.
READ_ALLOWED_PREFIXES: tuple[str, ...] = (
    "/api/core/firmware/",
    "/api/core/service/",
    "/api/core/system/",
    "/api/core/menu/",
    "/api/diagnostics/",
    "/api/dhcpv4/",
    "/api/dhcpv6/",
    "/api/dnsmasq/",
    "/api/kea/",
    "/api/firewall/alias/",
    "/api/firewall/filter/",
    "/api/ids/",
    "/api/interfaces/",
    "/api/routes/",
    "/api/unbound/",
)

# OPNsense paths are /api/<module>/<controller>/<command>. Commands are
# camelCase and start with a verb, so we match the command segment by prefix.
# Matching the whole path would be wrong: "settings" contains "set",
# "getAddresses" contains "add".
DENIED_COMMAND_PREFIXES: tuple[str, ...] = (
    "add",
    "apply",
    "cancel",
    "clear",
    "create",
    "del",
    "disable",
    "download",
    "drop",
    "edit",
    "enable",
    "exec",
    "flush",
    "generate",
    "halt",
    "import",
    "install",
    "kill",
    "lock",
    "new",
    "poweroff",
    "reboot",
    "reconfigure",
    "reload",
    "remove",
    "rename",
    "reset",
    "restart",
    "restore",
    "revert",
    "revoke",
    "rollback",
    "run",
    "save",
    "set",
    "sign",
    "start",
    "stop",
    "sync",
    "toggle",
    "unlock",
    "update",
    "upgrade",
    "upload",
)

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _normalise(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return path


def check_read_path(path: str) -> str:
    """Return the normalised path if it passes the read policy, else raise."""
    path = _normalise(path)

    if not path.isascii():
        raise PathNotAllowed(f"refused '{path}': non-ASCII characters")
    for bad in ("%", "?", "#", "\\", "//"):
        if bad in path:
            raise PathNotAllowed(f"refused '{path}': contains '{bad}'")

    segments = path.strip("/").split("/")
    for segment in segments:
        if segment in (".", ".."):
            raise PathNotAllowed(f"refused '{path}': dot segment")
        if not _SEGMENT_RE.match(segment):
            raise PathNotAllowed(f"refused '{path}': bad segment '{segment}'")

    # segments == ["api", module, controller, command, *args]
    if len(segments) >= 4:
        command = segments[3].lower()
        for verb in DENIED_COMMAND_PREFIXES:
            if command.startswith(verb):
                raise PathNotAllowed(
                    f"refused '{path}': command '{segments[3]}' starts with "
                    f"denied verb '{verb}' (this client is read-only)"
                )

    if not any(path.startswith(prefix) for prefix in READ_ALLOWED_PREFIXES):
        raise PathNotAllowed(f"refused '{path}': not under an allowed prefix")

    return path


class ReadClient:
    """Minimal async, GET-only client for the OPNsense REST API."""

    def __init__(
        self,
        settings: ReadSettings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self._http = httpx.AsyncClient(
            base_url=settings.url,
            auth=(
                settings.api_key.get_secret_value(),
                settings.api_secret.get_secret_value(),
            ),
            verify=settings.verify,
            timeout=settings.timeout,
            follow_redirects=False,
            headers={
                "Accept": "application/json",
                "User-Agent": f"opnsense-guard-mcp/{__version__}",
            },
            transport=transport,
        )

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Guarded GET. Raises PathNotAllowed or OPNsenseError."""
        path = check_read_path(path)

        try:
            response = await self._http.get(path, params=params)
        except httpx.ConnectTimeout as exc:
            raise OPNsenseError(f"timed out connecting to {self.settings.url}") from exc
        except httpx.ConnectError as exc:
            raise OPNsenseError(f"cannot reach {self.settings.url}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise OPNsenseError(f"request to {path} failed: {exc}") from exc

        status = response.status_code
        if status == 401:
            raise OPNsenseError("401 Unauthorized - API key/secret rejected by OPNsense")
        if status == 403:
            raise OPNsenseError(f"403 Forbidden - the API user lacks the privilege for {path}")
        if status == 404:
            raise OPNsenseError(f"404 Not Found - {path} does not exist on this version")
        if 300 <= status < 400:
            raise OPNsenseError(
                f"HTTP {status} redirect from {path} (not followed); "
                "usually means authentication failed"
            )
        if status >= 400:
            raise OPNsenseError(f"HTTP {status} from {path}: {response.text[:200]}")

        try:
            return response.json()
        except ValueError:
            raise OPNsenseError(
                f"expected JSON from {path} but got: {response.text[:200]!r}"
            ) from None

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> ReadClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
