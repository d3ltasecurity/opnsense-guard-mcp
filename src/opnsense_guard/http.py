"""Streamable HTTP transport with token auth, optional TLS and mTLS.

Startup rules (the server refuses to start otherwise):

* At least one token must exist. HTTP is never unauthenticated.
* Binding to a non-loopback address requires TLS, unless
  ``MCP_ALLOW_PLAINTEXT=true`` is set explicitly (e.g. behind a TLS proxy).
* A client CA (mTLS) requires a server certificate and key.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp

from opnsense_guard.auth import AuthMiddleware, TokenStore
from opnsense_guard.config import TRUTHY, ConfigError

DEFAULT_PORT = 8848


@dataclass
class HttpSettings:
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    tokens_file: Path = Path("tokens.json")
    tls_cert: Path | None = None
    tls_key: Path | None = None
    tls_client_ca: Path | None = None
    allow_plaintext: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_origins: list[str] = field(default_factory=list)
    rate_limit_per_min: int = 120

    @property
    def tls(self) -> bool:
        return self.tls_cert is not None

    def default_hosts(self) -> list[str]:
        """Host headers we accept when MCP_ALLOWED_HOSTS is not set."""
        names = {self.host, "localhost", "127.0.0.1", "[::1]"}
        return sorted(f"{name}:{self.port}" for name in names)


def _split(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _path(value: str | None) -> Path | None:
    return Path(value) if value else None


def http_settings_from_env() -> HttpSettings:
    env = os.environ
    try:
        port = int(env.get("MCP_PORT", str(DEFAULT_PORT)))
        rate = int(env.get("MCP_RATE_LIMIT_PER_MIN", "120"))
    except ValueError as exc:
        raise ConfigError(f"MCP_PORT / MCP_RATE_LIMIT_PER_MIN must be integers: {exc}") from exc
    settings = HttpSettings(
        host=env.get("MCP_HOST", "127.0.0.1"),
        port=port,
        tokens_file=Path(env.get("OPNSENSE_GUARD_TOKENS_FILE", "tokens.json")),
        tls_cert=_path(env.get("MCP_TLS_CERT")),
        tls_key=_path(env.get("MCP_TLS_KEY")),
        tls_client_ca=_path(env.get("MCP_TLS_CLIENT_CA")),
        allow_plaintext=env.get("MCP_ALLOW_PLAINTEXT", "false").lower() in TRUTHY,
        allowed_hosts=_split(env.get("MCP_ALLOWED_HOSTS")),
        allowed_origins=_split(env.get("MCP_ALLOWED_ORIGINS")),
        rate_limit_per_min=rate,
    )
    if not settings.allowed_hosts:
        settings.allowed_hosts = settings.default_hosts()
    return settings


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def validate_startup(settings: HttpSettings, store: TokenStore) -> None:
    """Raise ConfigError if the HTTP setup is unsafe."""
    if not store.entries():
        raise ConfigError(
            f"no tokens in {settings.tokens_file}. Create one first: "
            "opnsense-guard-mcp token new --name <client> --scope read"
        )
    if (settings.tls_cert is None) != (settings.tls_key is None):
        raise ConfigError("set both MCP_TLS_CERT and MCP_TLS_KEY, or neither")
    if settings.tls_client_ca and not settings.tls:
        raise ConfigError("MCP_TLS_CLIENT_CA (mTLS) needs MCP_TLS_CERT and MCP_TLS_KEY")
    for path in (settings.tls_cert, settings.tls_key, settings.tls_client_ca):
        if path is not None and not path.is_file():
            raise ConfigError(f"TLS file not found: {path}")
    if not is_loopback(settings.host) and not settings.tls and not settings.allow_plaintext:
        raise ConfigError(
            f"refusing to serve plain HTTP on non-loopback address {settings.host}: "
            "tokens would cross the network in clear text. Set MCP_TLS_CERT/MCP_TLS_KEY, "
            "or MCP_ALLOW_PLAINTEXT=true if a TLS proxy sits in front."
        )
    if not 1 <= settings.port <= 65535:
        raise ConfigError(f"MCP_PORT out of range: {settings.port}")


def build_http_app(mcp: MCPServer, settings: HttpSettings, store: TokenStore) -> ASGIApp:
    """The MCP Starlette app wrapped in our auth middleware."""
    inner = mcp.streamable_http_app(
        host=settings.host,
        # The SDK's own Host/Origin check, as a second layer behind ours.
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=settings.allowed_hosts,
            allowed_origins=settings.allowed_origins,
        ),
    )
    return AuthMiddleware(
        inner,
        store=store,
        allowed_hosts=settings.allowed_hosts,
        allowed_origins=settings.allowed_origins,
        rate_limit_per_min=settings.rate_limit_per_min,
    )


def run_http(mcp: MCPServer, settings: HttpSettings) -> None:
    import uvicorn

    store = TokenStore(settings.tokens_file)
    validate_startup(settings, store)
    app = build_http_app(mcp, settings, store)

    tls_kwargs: dict[str, object] = {}
    if settings.tls:
        tls_kwargs = {
            "ssl_certfile": str(settings.tls_cert),
            "ssl_keyfile": str(settings.tls_key),
        }
        if settings.tls_client_ca:
            tls_kwargs["ssl_ca_certs"] = str(settings.tls_client_ca)
            tls_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
        server_header=False,
        proxy_headers=False,
        **tls_kwargs,  # type: ignore[arg-type]
    )
