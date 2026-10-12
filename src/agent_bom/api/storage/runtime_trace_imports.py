"""Resume-state contract owned by the existing runtime observation backends."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.api.storage.runtime_records import RuntimeObservationRecord

RUNTIME_TRACE_STORAGE_VERSION = 4
TRACE_IMPORT_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS runtime_trace_imports (
        tenant_id TEXT NOT NULL,
        import_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        data TEXT NOT NULL,
        PRIMARY KEY (tenant_id, import_id)
    )
"""


class TraceImportConflictError(RuntimeError):
    """Another collector committed this page; reload the durable checkpoint."""


@dataclass(frozen=True)
class TraceImportCheckpoint:
    tenant_id: str
    import_id: str
    revision: int
    window_start: str
    window_end: str
    updated_at: str
    cursor: str | None = None
    complete: bool = False
    scope_key: str = ""
    rejected_count: int = 0

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value or len(value) > 512 for value in (self.tenant_id, self.import_id)):
            raise ValueError("Trace import scope is invalid")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or not 1 <= self.revision < 2**31:
            raise ValueError("Trace import revision is invalid")
        if self.cursor is not None and (not isinstance(self.cursor, str) or not self.cursor or len(self.cursor) > 8192):
            raise ValueError("Trace import cursor is invalid")
        if not isinstance(self.complete, bool) or (self.complete and self.cursor is not None):
            raise ValueError("Completed trace import cannot retain a next cursor")
        if not isinstance(self.scope_key, str) or len(self.scope_key) > 512:
            raise ValueError("Trace import scope key is invalid")
        if isinstance(self.rejected_count, bool) or not isinstance(self.rejected_count, int) or self.rejected_count < 0:
            raise ValueError("Trace import rejected count is invalid")
        moments = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in (self.window_start, self.window_end, self.updated_at)]
        if any(moment.tzinfo is None for moment in moments) or moments[0] >= moments[1]:
            raise ValueError("Trace import requires a bounded timezone-aware window")


def validate_page(checkpoint: TraceImportCheckpoint, records: list[RuntimeObservationRecord], expected_revision: int) -> None:
    if checkpoint.revision != expected_revision + 1 or expected_revision < 0:
        raise ValueError("Trace import revision must advance by one")
    if any(record.tenant_id != checkpoint.tenant_id for record in records):
        raise ValueError("Trace import page must belong to its checkpoint tenant")


def check_revision(current: TraceImportCheckpoint | None, expected_revision: int, next_checkpoint: TraceImportCheckpoint) -> None:
    if (current.revision if current else 0) != expected_revision:
        raise TraceImportConflictError("Trace import checkpoint changed; resume from the committed page")
    if current is not None:
        if current.scope_key != next_checkpoint.scope_key or next_checkpoint.rejected_count < current.rejected_count:
            raise ValueError("Trace import scope and rejected evidence cannot change while resuming")
        if current.complete:
            raise ValueError("Trace import is complete; use a new import for a new collection")
        if (current.window_start, current.window_end) != (next_checkpoint.window_start, next_checkpoint.window_end):
            raise ValueError("Trace import window cannot change while resuming")


def read_checkpoint(conn: Any, tenant_id: str, import_id: str, *, placeholder: str = "?") -> TraceImportCheckpoint | None:
    if placeholder not in {"?", "%s"}:
        raise ValueError("Unsupported SQL placeholder")
    row = conn.execute(
        f"SELECT data FROM runtime_trace_imports WHERE tenant_id = {placeholder} AND import_id = {placeholder}",  # nosec B608
        (tenant_id, import_id),
    ).fetchone()
    return TraceImportCheckpoint(**json.loads(row[0])) if row else None


def write_checkpoint(conn: Any, checkpoint: TraceImportCheckpoint, *, placeholder: str = "?") -> None:
    if placeholder not in {"?", "%s"}:
        raise ValueError("Unsupported SQL placeholder")
    params = ",".join([placeholder] * 4)
    conn.execute(
        f"INSERT INTO runtime_trace_imports (tenant_id,import_id,revision,data) VALUES ({params}) "  # nosec B608
        "ON CONFLICT (tenant_id,import_id) DO UPDATE SET revision=excluded.revision,data=excluded.data",
        (checkpoint.tenant_id, checkpoint.import_id, checkpoint.revision, json.dumps(asdict(checkpoint), sort_keys=True)),
    )
