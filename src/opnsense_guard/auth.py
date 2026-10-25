"""Bearer-token auth for the HTTP transport.

Tokens are random 256-bit strings shown once at creation. Only their SHA-256
is stored (high-entropy secrets do not need a slow hash). Each token has a
name, used in logs and later in the audit trail, and a scope:

* ``read``  - may call read tools only
* ``write`` - may also call write tools (once they exist)

The token file is re-read when it changes on disk, so revoking a token takes
effect on the next request without a restart.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger("opnsense_guard.auth")

TokenScope = Literal["read", "write"]
SCOPES: tuple[TokenScope, ...] = ("read", "write")
TOKEN_PREFIX = "ogm_"  # noqa: S105 - public prefix, not a secret
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")


class TokenError(RuntimeError):
    """Problem with the token file or a token operation."""


@dataclass(frozen=True)
class TokenEntry:
    name: str
    scope: TokenScope
    sha256: str
    created: str


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenStore:
    """Token file on disk: ``{"version": 1, "tokens": [...]}``."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._entries: list[TokenEntry] = []
        self._mtime: float | None = None

    # ------------------------------------------------------------ loading

    def _read(self) -> list[TokenEntry]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            entries = [
                TokenEntry(
                    name=str(t["name"]),
                    scope=t["scope"],
                    sha256=str(t["sha256"]),
                    created=str(t.get("created", "")),
                )
                for t in data.get("tokens", [])
            ]
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise TokenError(f"token file {self.path} is malformed: {exc}") from exc
        for entry in entries:
            if entry.scope not in SCOPES:
                raise TokenError(f"token '{entry.name}' has unknown scope '{entry.scope}'")
        return entries

    def entries(self) -> list[TokenEntry]:
        """Current entries, reloading if the file changed."""
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            mtime = None
        if mtime != self._mtime:
            self._entries = self._read()
            self._mtime = mtime
        return list(self._entries)

    def verify(self, token: str) -> TokenEntry | None:
        """Return the matching entry, comparing every hash in constant time."""
        candidate = hash_token(token)
        match: TokenEntry | None = None
        for entry in self.entries():
            if hmac.compare_digest(candidate, entry.sha256):
                match = entry
        return match

    # ---------------------------------------------------------- mutating

    def _write(self, entries: list[TokenEntry]) -> None:
        payload = {
            "version": 1,
            "tokens": [entry.__dict__ for entry in entries],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        self._mtime = None  # force reload

    def create(self, name: str, scope: TokenScope) -> str:
        """Create a token and return the plaintext. It is not stored."""
        if not NAME_RE.match(name):
            raise TokenError("name must be 1-64 chars: letters, digits, _ . -")
        if scope not in SCOPES:
            raise TokenError(f"scope must be one of {', '.join(SCOPES)}")
        entries = self.entries()
        if any(e.name == name for e in entries):
            raise TokenError(f"a token named '{name}' already exists")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        entries.append(
            TokenEntry(
                name=name,
                scope=scope,
                sha256=hash_token(token),
                created=datetime.now(UTC).isoformat(timespec="seconds"),
            )
        )
        self._write(entries)
        return token

    def revoke(self, name: str) -> None:
        entries = self.entries()
        kept = [e for e in entries if e.name != name]
        if len(kept) == len(entries):
            raise TokenError(f"no token named '{name}'")
        self._write(kept)


class SlidingWindow:
    """Per-key request counter over the last ``window`` seconds."""

    def __init__(self, limit: int, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        hits = self._hits[key]
        while hits and now - hits[0] >= self.window:
            hits.popleft()
        return hits

    def full(self, key: str, now: float | None = None) -> bool:
        """True if ``key`` has used up its budget (does not count a hit)."""
        now = time.monotonic() if now is None else now
        return len(self._prune(key, now)) >= self.limit

    def allow(self, key: str, now: float | None = None) -> bool:
        """Count a hit for ``key``; False if the budget was already used up."""
        now = time.monotonic() if now is None else now
        hits = self._prune(key, now)
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


def _host_allowed(host: str, allowed: list[str]) -> bool:
    for pattern in allowed:
        if host == pattern:
            return True
        if pattern.endswith(":*") and host.startswith(pattern[:-1]):
            return True
    return False


class AuthMiddleware:
    """ASGI middleware: Host/Origin checks, bearer auth, rate limits.

    Runs before the MCP app on every HTTP request. Lifespan and other
    non-HTTP events pass straight through.
    """

    def __init__(
        self,
        app: ASGIApp,
        store: TokenStore,
        allowed_hosts: list[str],
        allowed_origins: list[str],
        rate_limit_per_min: int = 120,
        auth_failures_per_min: int = 10,
    ) -> None:
        self.app = app
        self.store = store
        self.allowed_hosts = allowed_hosts
        self.allowed_origins = allowed_origins
        self.rate = SlidingWindow(rate_limit_per_min)
        self.failures = SlidingWindow(auth_failures_per_min)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"

        # DNS-rebinding defence: Host must be one we serve; a browser Origin
        # must be explicitly allowed (non-browser clients send none).
        if not _host_allowed(headers.get("host", ""), self.allowed_hosts):
            await _reject(send, 421, "invalid Host header")
            return
        origin = headers.get("origin")
        if origin and not _host_allowed(origin, self.allowed_origins):
            await _reject(send, 403, "Origin not allowed")
            return

        # Clients that keep failing are slowed down before we even hash.
        if self.failures.full(client_ip):
            await _reject(send, 429, "too many failed authentication attempts")
            return

        auth = headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        entry = self.store.verify(token.strip()) if scheme.lower() == "bearer" and token else None
        if entry is None:
            self.failures.allow(client_ip)
            log.warning("auth failed from %s", client_ip)
            await _reject(send, 401, "missing or invalid bearer token", bearer=True)
            return

        if not self.rate.allow(entry.name):
            await _reject(send, 429, "rate limit exceeded")
            return

        state: dict[str, Any] = scope.setdefault("state", {})
        state["token_name"] = entry.name
        state["token_scope"] = entry.scope
        await self.app(scope, receive, send)


async def _reject(send: Send, status: int, message: str, bearer: bool = False) -> None:
    body = json.dumps({"error": message}).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    if bearer:
        headers.append((b"www-authenticate", b'Bearer realm="opnsense-guard-mcp"'))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
