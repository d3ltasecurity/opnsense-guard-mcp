"""Append-only, hash-chained audit log (JSONL).

Each line is a JSON object with ``prev_hash`` (the previous line's ``hash``)
and ``hash`` = SHA-256 over the canonical JSON of the line without ``hash``.
Editing, deleting or reordering lines breaks the chain, which
``opnsense-guard-mcp audit verify`` detects.

Secrets never reach the log: keys that look like credentials are redacted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
_SECRET_KEY_RE = re.compile(r"(secret|password|passwd|api_?key|authorization|bearer|^token$)", re.I)
REDACTED = "[redacted]"


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


def redact(value: Any) -> Any:
    """Recursively replace values under credential-looking keys."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if _SECRET_KEY_RE.search(str(k)) else redact(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._last_hash: str | None = None

    def _tail_hash(self) -> str:
        if self._last_hash is not None:
            return self._last_hash
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        """Write one event and return the stored record."""
        with self._lock:
            record: dict[str, Any] = {
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "event": event,
                **redact(fields),
                "prev_hash": self._tail_hash(),
            }
            record["hash"] = _hash(record)

            self.path.parent.mkdir(parents=True, exist_ok=True)
            new_file = not self.path.exists()
            with self.path.open("ab") as fh:
                fh.write(_canonical(record) + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
            if new_file and os.name == "posix":
                os.chmod(self.path, 0o600)
            self._last_hash = record["hash"]
            return record

    def tail(self, n: int) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return [json.loads(ln) for ln in lines[-n:]]


def verify(path: Path) -> tuple[bool, int, str]:
    """Check the whole chain. Returns (ok, lines_checked, message)."""
    if not path.exists():
        return True, 0, "no audit log yet"
    prev = GENESIS
    count = 0
    with path.open("rb") as fh:
        for number, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                return False, count, f"line {number}: not valid JSON"
            stored = record.pop("hash", None)
            if record.get("prev_hash") != prev:
                return False, count, f"line {number}: chain broken (prev_hash mismatch)"
            if stored != _hash(record):
                return False, count, f"line {number}: content was modified (hash mismatch)"
            prev = stored
            count += 1
    return True, count, f"ok: {count} events, chain intact"
