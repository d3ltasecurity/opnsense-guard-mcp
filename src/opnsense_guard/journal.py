"""Change journal: every applied change, with before/after snapshots.

SQLite on disk with synchronous=FULL, written *before* anything is sent to
the firewall, so a crash mid-change still leaves enough to revert it.

Status flow::

    applying -> pending -> confirmed
                       \\-> reverted          (timer, rollback, or restart)
             \\-> failed                      (apply error; partial work undone)
    any revert can end in revert_failed or conflict (object edited by someone else)
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

ChangeStatus = Literal[
    "applying", "pending", "confirmed", "reverted", "failed", "revert_failed", "conflict"
]
OPEN_STATUSES = ("applying", "pending")
_SELECT = (
    "SELECT id, plan_id, kind, actor, status, created, updated, deadline, objects, "
    "error, confirm_method FROM changes "
)


@dataclass
class ChangeObject:
    type: Literal["rule", "alias"]
    op: str
    ref: str  # rule uuid / alias name; "(new)" until an add returns its uuid
    before: dict[str, Any] | None
    planned: dict[str, Any] | None  # the after-state the plan promised
    uuid: str | None = None  # rule/alias uuid actually touched (new uuid for adds)
    after: dict[str, Any] | None = None  # state read back after apply
    done: bool = False  # the write for this object was sent successfully
    reverted_uuid: str | None = None  # new uuid when a delete was undone by re-adding


@dataclass
class Change:
    id: str
    plan_id: str
    kind: Literal["rule", "alias"]
    actor: str
    status: ChangeStatus
    created: float
    deadline: float | None
    objects: list[ChangeObject] = field(default_factory=list)
    error: str | None = None
    confirm_method: str | None = None
    updated: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Same key as failure results and the change_* tool arguments.
        data["change_id"] = self.id
        data["seconds_left"] = (
            max(0, round(self.deadline - time.time())) if self.deadline and self.open else None
        )
        return data

    @property
    def open(self) -> bool:
        return self.status in OPEN_STATUSES


def new_change_id() -> str:
    return "c_" + secrets.token_hex(8)


class Journal:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        new = not path.exists()
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS changes (
                id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                actor TEXT NOT NULL,
                status TEXT NOT NULL,
                created REAL NOT NULL,
                updated REAL NOT NULL,
                deadline REAL,
                objects TEXT NOT NULL,
                error TEXT,
                confirm_method TEXT
            )"""
        )
        if new and os.name == "posix":
            os.chmod(path, 0o600)

    def save(self, change: Change) -> None:
        change.updated = time.time()
        row = (
            change.id,
            change.plan_id,
            change.kind,
            change.actor,
            change.status,
            change.created,
            change.updated,
            change.deadline,
            json.dumps([asdict(o) for o in change.objects]),
            change.error,
            change.confirm_method,
        )
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO changes (id, plan_id, kind, actor, status, created, "
                "updated, deadline, objects, error, confirm_method) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                row,
            )

    @staticmethod
    def _load(row: tuple[Any, ...]) -> Change:
        (cid, plan_id, kind, actor, status, created, updated, deadline, objects, error, method) = (
            row
        )
        return Change(
            id=cid,
            plan_id=plan_id,
            kind=kind,
            actor=actor,
            status=status,
            created=created,
            updated=updated,
            deadline=deadline,
            objects=[ChangeObject(**o) for o in json.loads(objects)],
            error=error,
            confirm_method=method,
        )

    def _query(self, sql: str, params: tuple[Any, ...] = ()) -> list[Change]:
        with self._lock:
            # `sql` is always one of the fixed WHERE/ORDER clauses in this class;
            # user values only ever travel as bound parameters.
            query = _SELECT + sql
            rows = self._db.execute(query, params).fetchall()
        return [self._load(r) for r in rows]

    def get(self, change_id: str) -> Change | None:
        found = self._query("WHERE id = ?", (change_id,))
        return found[0] if found else None

    def recent(self, limit: int = 20) -> list[Change]:
        return self._query("ORDER BY created DESC LIMIT ?", (limit,))

    def open_changes(self) -> list[Change]:
        return self._query("WHERE status IN ('applying', 'pending') ORDER BY created")

    def plan_used(self, plan_id: str) -> bool:
        return bool(self._query("WHERE plan_id = ?", (plan_id,)))

    def count_since(self, since: float) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) FROM changes WHERE created >= ?", (since,)
            ).fetchone()
        return int(row[0])

    def close(self) -> None:
        with self._lock:
            self._db.close()
