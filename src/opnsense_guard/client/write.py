"""Write client: POST only, to an exact list of firewall endpoints.

Separate from ReadClient on purpose:

1. Different identity (OPNSENSE_WRITE_API_KEY/SECRET), so reads and writes
   show up as different users in OPNsense's own audit trail.
2. Every path must match one of WRITE_ENDPOINTS exactly (full regex match,
   UUIDs validated). Nothing system-level is reachable: no reboot, firmware,
   services, users, certificates or config backups.
3. No write credentials configured -> no write client, and the server does
   not register any change tools.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx
from pydantic import SecretStr

from opnsense_guard import __version__
from opnsense_guard.client.read import OPNsenseError, PathNotAllowed
from opnsense_guard.config import ConfigError, ReadSettings, read_settings_from_env

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

WRITE_ENDPOINTS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"/api/firewall/filter/addRule",
        rf"/api/firewall/filter/setRule/{_UUID}",
        rf"/api/firewall/filter/delRule/{_UUID}",
        rf"/api/firewall/filter/toggleRule/{_UUID}/[01]",
        r"/api/firewall/filter/apply",
        r"/api/firewall/alias/addItem",
        rf"/api/firewall/alias/setItem/{_UUID}",
        rf"/api/firewall/alias/delItem/{_UUID}",
        r"/api/firewall/alias/reconfigure",
    )
)


def check_write_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    if not any(pattern.fullmatch(path) for pattern in WRITE_ENDPOINTS):
        raise PathNotAllowed(f"refused write to '{path}': not an allowed write endpoint")
    return path


def write_settings_from_env() -> ReadSettings | None:
    """Settings for the write user, or None if write credentials are not set."""
    key = os.environ.get("OPNSENSE_WRITE_API_KEY")
    secret = os.environ.get("OPNSENSE_WRITE_API_SECRET")
    if not key and not secret:
        return None
    if not key or not secret:
        raise ConfigError("set both OPNSENSE_WRITE_API_KEY and OPNSENSE_WRITE_API_SECRET")
    base = read_settings_from_env()
    if key == base.api_key.get_secret_value():
        raise ConfigError("the write API key must belong to a different user than the read key")
    return base.model_copy(update={"api_key": SecretStr(key), "api_secret": SecretStr(secret)})


class WriteClient:
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

    async def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """Guarded POST. Raises PathNotAllowed or OPNsenseError."""
        path = check_write_path(path)
        try:
            response = await self._http.post(path, json=body if body is not None else {})
        except httpx.HTTPError as exc:
            raise OPNsenseError(f"write to {path} failed: {exc}") from exc

        status = response.status_code
        if status == 401:
            raise OPNsenseError("401 Unauthorized - write API key/secret rejected")
        if status == 403:
            raise OPNsenseError(
                f"403 Forbidden - the write user lacks the privilege for {path} "
                "(or has 'config read-only' set)"
            )
        if status >= 300:
            raise OPNsenseError(f"HTTP {status} from {path}: {response.text[:200]}")
        try:
            data = response.json()
        except ValueError:
            raise OPNsenseError(f"expected JSON from {path}: {response.text[:200]!r}") from None

        # OPNsense reports validation failures with HTTP 200.
        if isinstance(data, dict) and data.get("result") == "failed":
            raise OPNsenseError(f"OPNsense refused {path}: {data.get('validations') or data}")
        return data

    async def aclose(self) -> None:
        await self._http.aclose()
