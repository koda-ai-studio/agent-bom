"""Advisory AI assessments persisted with their scan; every read and write names a tenant.

A separate table rather than the scan report: the findings list needs the newest
assessment for one page of findings without loading a single report.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Sequence
from typing import Any, Protocol

from agent_bom.api.postgres_common import _ensure_tenant_rls, _get_pool, _maintenance_connection, _tenant_connection, bypass_tenant_rls
from agent_bom.api.storage.sql import SQLiteBackend
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.storage.base import BackendKind
from agent_bom.storage.factory import resolve_backend

_logger = logging.getLogger(__name__)
MAX_FINDING_LOOKUP = 3_000  # a 1,000-row page carries up to three identifiers per row


class AIAssessmentStore(Protocol):
    def put_scan(self, tenant_id: str, scan_id: str, run: dict[str, Any], assessments: Sequence[dict[str, Any]]) -> None:
        """Persist one triage run and its per-finding assessments."""

    def latest_for_findings(self, tenant_id: str, finding_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        """Return the newest assessment per finding id."""

    def latest_run(self, tenant_id: str) -> dict[str, Any] | None:
        """Return the tenant's most recent triage run, if any."""

    def delete_scan(self, tenant_id: str, scan_id: str) -> int:
        """Delete one scan's assessments; return the rows removed."""

    def purge_tenant(self, tenant_id: str) -> int:
        """Delete every assessment for a tenant; return the rows removed."""

    def delete_older_than(self, cutoff_iso: str) -> int:
        """Delete assessments older than ``cutoff_iso``; return the rows removed."""


def _stored(item: dict[str, Any], scan_id: str, created_at: str) -> dict[str, Any]:
    return {**item, "scan_id": scan_id, "stored_at": created_at}


def _bounded(finding_ids: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in finding_ids if item))[:MAX_FINDING_LOOKUP]


class InMemoryAIAssessmentStore:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._runs: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def put_scan(self, tenant_id: str, scan_id: str, run: dict[str, Any], assessments: Sequence[dict[str, Any]]) -> None:
        created_at = str(run["created_at"])
        with self._lock:
            for key in [key for key in self._rows if key[:2] == (tenant_id, scan_id)]:
                del self._rows[key]
            self._runs[(tenant_id, scan_id)] = {**run, "scan_id": scan_id}
            for item in assessments:
                self._rows[(tenant_id, scan_id, str(item["finding_id"]))] = {**item, "scan_id": scan_id, "stored_at": created_at}

    def latest_for_findings(self, tenant_id: str, finding_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        wanted = set(_bounded(finding_ids))
        latest: dict[str, dict[str, Any]] = {}
        with self._lock:
            for (tenant, _scan, finding_id), row in self._rows.items():
                if tenant == tenant_id and finding_id in wanted:
                    current = latest.get(finding_id)
                    if current is None or row["stored_at"] > current["stored_at"]:
                        latest[finding_id] = row
        return latest

    def latest_run(self, tenant_id: str) -> dict[str, Any] | None:
        with self._lock:
            runs = [run for (tenant, _scan), run in self._runs.items() if tenant == tenant_id]
        return max(runs, key=lambda run: str(run["created_at"])) if runs else None

    def delete_scan(self, tenant_id: str, scan_id: str) -> int:
        with self._lock:
            keys = [key for key in self._rows if key[:2] == (tenant_id, scan_id)]
            for key in keys:
                del self._rows[key]
            removed_run = self._runs.pop((tenant_id, scan_id), None)
        return len(keys) + int(removed_run is not None)

    def delete_older_than(self, cutoff_iso: str) -> int:
        with self._lock:
            keys = [key for key, row in self._rows.items() if str(row["stored_at"]) < cutoff_iso]
            runs = [key for key, run in self._runs.items() if str(run["created_at"]) < cutoff_iso]
            for key in keys:
                del self._rows[key]
            for run_key in runs:
                del self._runs[run_key]
        return len(keys) + len(runs)

    def purge_tenant(self, tenant_id: str) -> int:
        with self._lock:
            keys = [key for key in self._rows if key[0] == tenant_id]
            runs = [key for key in self._runs if key[0] == tenant_id]
            for key in keys:
                del self._rows[key]
            for run_key in runs:
                del self._runs[run_key]
        return len(keys) + len(runs)


_SQLITE_DDL = (
    """
    CREATE TABLE IF NOT EXISTS ai_finding_assessments (
        tenant_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        data TEXT NOT NULL,
        PRIMARY KEY (tenant_id, scan_id, finding_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ai_finding_assessments_latest ON ai_finding_assessments(tenant_id, finding_id, created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS ai_triage_runs (
        tenant_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        data TEXT NOT NULL,
        PRIMARY KEY (tenant_id, scan_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ai_triage_runs_latest ON ai_triage_runs(tenant_id, created_at DESC)",
)


class SQLiteAIAssessmentStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._backend = SQLiteBackend(db_path)
        self._backend.bootstrap("ai_triage", {"sqlite": _SQLITE_DDL})

    def put_scan(self, tenant_id: str, scan_id: str, run: dict[str, Any], assessments: Sequence[dict[str, Any]]) -> None:
        created_at = str(run["created_at"])
        with self._backend.transaction() as tx:
            tx.execute("DELETE FROM ai_finding_assessments WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))
            tx.execute(
                "INSERT OR REPLACE INTO ai_triage_runs (tenant_id, scan_id, created_at, data) VALUES (?, ?, ?, ?)",
                (tenant_id, scan_id, created_at, json.dumps({**run, "scan_id": scan_id})),
            )
            for item in assessments:
                tx.execute(
                    "INSERT OR REPLACE INTO ai_finding_assessments (tenant_id, scan_id, finding_id, created_at, data) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        scan_id,
                        str(item["finding_id"]),
                        created_at,
                        json.dumps({**item, "scan_id": scan_id, "stored_at": created_at}),
                    ),
                )

    def latest_for_findings(self, tenant_id: str, finding_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        wanted = _bounded(finding_ids)
        if not wanted:
            return {}
        marks = ",".join("?" for _ in wanted)
        rows = self._backend._conn().execute(
            "SELECT finding_id, data FROM ai_finding_assessments "  # nosec B608 - placeholders only; values are bound
            f"WHERE tenant_id = ? AND finding_id IN ({marks}) ORDER BY finding_id, created_at ASC",
            (tenant_id, *wanted),
        )
        return {str(row[0]): json.loads(row[1]) for row in rows.fetchall()}

    def latest_run(self, tenant_id: str) -> dict[str, Any] | None:
        # fetchall finishes the statement; a half-read one would pin this connection to an old WAL snapshot.
        rows = (
            self._backend._conn()
            .execute("SELECT data FROM ai_triage_runs WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1", (tenant_id,))
            .fetchall()
        )
        return json.loads(rows[0][0]) if rows else None

    def _delete(self, predicate: str, values: tuple[str, ...]) -> int:
        removed = 0
        with self._backend.transaction() as tx:
            for table in ("ai_finding_assessments", "ai_triage_runs"):
                cursor = tx.execute(f"DELETE FROM {table} WHERE {predicate}", values)  # nosec B608 - fixed identifiers; values are bound
                removed += max(cursor.rowcount or 0, 0)
        return removed

    def delete_scan(self, tenant_id: str, scan_id: str) -> int:
        return self._delete("tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))

    def purge_tenant(self, tenant_id: str) -> int:
        return self._delete("tenant_id = ?", (tenant_id,))

    def delete_older_than(self, cutoff_iso: str) -> int:
        return self._delete("created_at < ?", (cutoff_iso,))


_POSTGRES_DDL = (
    """
    CREATE TABLE IF NOT EXISTS ai_finding_assessments (
        tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
        scan_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        data JSONB NOT NULL,
        PRIMARY KEY (tenant_id, scan_id, finding_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ai_finding_assessments_latest ON ai_finding_assessments (tenant_id, finding_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_ai_finding_assessments_created ON ai_finding_assessments (created_at)",
    """
    CREATE TABLE IF NOT EXISTS ai_triage_runs (
        tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
        scan_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        data JSONB NOT NULL,
        PRIMARY KEY (tenant_id, scan_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ai_triage_runs_latest ON ai_triage_runs (tenant_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_ai_triage_runs_created ON ai_triage_runs (created_at)",
)


class PostgresAIAssessmentStore:
    def __init__(self, pool: Any = None) -> None:
        self._injected_pool = pool
        with self._pool.connection() as conn:
            if ensure_postgres_schema_version(conn, "ai_triage", version=1):
                for statement in _POSTGRES_DDL:
                    conn.execute(statement)
                _ensure_tenant_rls(conn, "ai_finding_assessments", "tenant_id")
                _ensure_tenant_rls(conn, "ai_triage_runs", "tenant_id")
                conn.commit()

    @property
    def _pool(self) -> Any:
        # The shared pool can be replaced after a reset, so this long-lived store never keeps it.
        return self._injected_pool or _get_pool()

    def put_scan(self, tenant_id: str, scan_id: str, run: dict[str, Any], assessments: Sequence[dict[str, Any]]) -> None:
        from psycopg.types.json import Jsonb

        require_explicit_tenant_id(tenant_id)
        created_at = str(run["created_at"])
        with _tenant_connection(self._pool) as conn:
            conn.execute("DELETE FROM ai_finding_assessments WHERE tenant_id=%s AND scan_id=%s", (tenant_id, scan_id))
            conn.execute(
                "INSERT INTO ai_triage_runs (tenant_id, scan_id, created_at, data) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (tenant_id, scan_id) DO UPDATE SET created_at=excluded.created_at, data=excluded.data",
                (tenant_id, scan_id, created_at, Jsonb({**run, "scan_id": scan_id})),
            )
            for item in assessments:
                conn.execute(
                    "INSERT INTO ai_finding_assessments (tenant_id, scan_id, finding_id, created_at, data) VALUES (%s, %s, %s, %s, %s) "
                    "ON CONFLICT (tenant_id, scan_id, finding_id) DO UPDATE SET created_at=excluded.created_at, data=excluded.data",
                    (tenant_id, scan_id, str(item["finding_id"]), created_at, Jsonb(_stored(item, scan_id, created_at))),
                )
            conn.commit()

    def latest_for_findings(self, tenant_id: str, finding_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        require_explicit_tenant_id(tenant_id)
        wanted = _bounded(finding_ids)
        if not wanted:
            return {}
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT DISTINCT ON (finding_id) finding_id, data FROM ai_finding_assessments "
                "WHERE tenant_id=%s AND finding_id = ANY(%s) ORDER BY finding_id, created_at DESC",
                (tenant_id, wanted),
            ).fetchall()
        return {str(row[0]): row[1] for row in rows}

    def latest_run(self, tenant_id: str) -> dict[str, Any] | None:
        require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM ai_triage_runs WHERE tenant_id=%s ORDER BY created_at DESC LIMIT 1", (tenant_id,)
            ).fetchone()
        return row[0] if row else None

    def _delete(self, predicate: str, values: tuple[str, ...]) -> int:
        require_explicit_tenant_id(values[0])
        removed = 0
        with _tenant_connection(self._pool) as conn:
            for table in ("ai_finding_assessments", "ai_triage_runs"):
                removed += conn.execute(f"DELETE FROM {table} WHERE {predicate}", values).rowcount or 0  # nosec B608 - fixed identifiers; values are bound
            conn.commit()
        return removed

    def delete_scan(self, tenant_id: str, scan_id: str) -> int:
        return self._delete("tenant_id=%s AND scan_id=%s", (tenant_id, scan_id))

    def purge_tenant(self, tenant_id: str) -> int:
        return self._delete("tenant_id=%s", (tenant_id,))

    def delete_older_than(self, cutoff_iso: str) -> int:
        # The global TTL sweep spans tenants, so it runs under the maintenance role like job expiry.
        removed = 0
        with bypass_tenant_rls(audit=False, warn=False):
            with _maintenance_connection() as conn:
                for table in ("ai_finding_assessments", "ai_triage_runs"):
                    removed += conn.execute(f"DELETE FROM {table} WHERE created_at < %s", (cutoff_iso,)).rowcount or 0  # nosec B608 - fixed identifiers; values are bound
                conn.commit()
        return removed


_STORE: AIAssessmentStore | None = None
_STORE_LOCK = threading.Lock()


def get_ai_assessment_store() -> AIAssessmentStore:
    global _STORE
    if _STORE is not None:
        return _STORE
    with _STORE_LOCK:
        if _STORE is None:
            selection = resolve_backend()
            if selection.backend is BackendKind.POSTGRES:
                _STORE = PostgresAIAssessmentStore()
            elif selection.backend is BackendKind.SQLITE:
                _STORE = SQLiteAIAssessmentStore(selection.sqlite_path or "")
            else:
                _STORE = InMemoryAIAssessmentStore()
        return _STORE


def set_ai_assessment_store(store: AIAssessmentStore | None) -> None:
    global _STORE
    _STORE = store


def discard_scan_advice(tenant_id: str, scan_id: str) -> None:
    """Derived-data cleanup: a failure here never fails the job delete or the maintenance loop, and the TTL sweep retries."""
    try:
        get_ai_assessment_store().delete_scan(tenant_id, scan_id)
    except Exception as exc:  # broad-except: driver errors have no common base, and this is derived data
        _logger.warning("AI advice delete skipped: %s", type(exc).__name__)


def expire_advice(cutoff_iso: str) -> None:
    try:
        get_ai_assessment_store().delete_older_than(cutoff_iso)
    except Exception as exc:  # broad-except: driver errors have no common base, and this is derived data
        _logger.warning("AI advice expiry skipped: %s", type(exc).__name__)
