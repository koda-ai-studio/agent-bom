"""Tenant-scoped runtime session and observation persistence."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections import Counter
from typing import Any, Protocol

from agent_bom.analytics_retention import prune_runtime_observations_for_tenant
from agent_bom.api.gateway_activity_store import ensure_sqlite_gateway_activity_schema
from agent_bom.api.storage.runtime_observation_query import memory_observation_page, session_keys, sql_observation_page, sql_sessions
from agent_bom.api.storage.runtime_records import (
    RuntimeObservationRecord as RuntimeObservationRecord,
)
from agent_bom.api.storage.runtime_records import (
    RuntimeSessionRecord as RuntimeSessionRecord,
)
from agent_bom.api.storage.runtime_records import (
    _observation_from_json as _observation_from_json,
)
from agent_bom.api.storage.runtime_records import (
    _session_from_json as _session_from_json,
)
from agent_bom.api.storage.runtime_records import (
    sanitize_runtime_metadata as sanitize_runtime_metadata,
)
from agent_bom.api.storage.runtime_trace_imports import (
    RUNTIME_TRACE_STORAGE_VERSION,
    TRACE_IMPORT_TABLE_SQL,
    TraceImportCheckpoint,
    check_revision,
    read_checkpoint,
    validate_page,
    write_checkpoint,
)
from agent_bom.api.storage.runtime_trace_revisions import (
    REVISION_TABLE_SQL,
    TracePageCommit,
    content_hash,
    read_revisions,
    reconcile_sql,
    revised_session,
)
from agent_bom.api.storage_schema import ensure_sqlite_schema_version

_BATCH_LOOKUP_CHUNK = 500


def _dedupe_observation_records(records: list[RuntimeObservationRecord]) -> list[RuntimeObservationRecord]:
    if records and (not records[0].tenant_id or any(record.tenant_id != records[0].tenant_id for record in records)):
        raise ValueError("Runtime observation batches must belong to one tenant")
    seen: set[tuple[str, str]] = set()
    unique: list[RuntimeObservationRecord] = []
    for record in records:
        key = (record.tenant_id, record.observation_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return unique


def _merge_sessions_for_batch(
    existing_sessions: dict[str, RuntimeSessionRecord],
    new_records: list[RuntimeObservationRecord],
) -> dict[str, RuntimeSessionRecord]:
    sessions = dict(existing_sessions)
    for record in new_records:
        sessions[record.session_id] = _merge_session(sessions.get(record.session_id), record)
    return sessions


class RuntimeEventStore(Protocol):
    def get_trace_import(self, tenant_id: str, import_id: str) -> TraceImportCheckpoint | None: ...

    def commit_trace_page(
        self, checkpoint: TraceImportCheckpoint, records: list[RuntimeObservationRecord], *, expected_revision: int
    ) -> TracePageCommit: ...

    def list_observation_revisions(
        self, tenant_id: str, observation_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeObservationRecord]: ...

    def put_observation(self, record: RuntimeObservationRecord) -> None: ...

    def put_observations_batch(self, records: list[RuntimeObservationRecord]) -> int: ...

    def query_observations(self, tenant_id: str, *, limit: int = 100, offset: int = 0, **filters: Any) -> dict[str, Any]: ...

    def list_sessions(self, tenant_id: str, *, limit: int = 100, offset: int = 0) -> list[RuntimeSessionRecord]: ...

    def get_session(self, tenant_id: str, session_id: str) -> RuntimeSessionRecord | None: ...

    def get_sessions(self, tenant_id: str, session_ids: list[str]) -> list[RuntimeSessionRecord]: ...

    def list_observations(
        self,
        tenant_id: str,
        *,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RuntimeObservationRecord]: ...


def _merge_session(existing: RuntimeSessionRecord | None, observation: RuntimeObservationRecord) -> RuntimeSessionRecord:
    event_types = Counter(existing.event_types if existing else {})
    verdicts = Counter(existing.verdicts if existing else {})
    severities = Counter(existing.severities if existing else {})
    tools = set(existing.tools if existing else [])
    if observation.event_type:
        event_types[observation.event_type] += 1
    if observation.verdict:
        verdicts[observation.verdict] += 1
    if observation.severity:
        severities[observation.severity] += 1
    if observation.tool_name:
        tools.add(observation.tool_name)

    first_seen = min(existing.first_seen, observation.observed_at) if existing else observation.observed_at
    last_seen = max(existing.last_seen, observation.observed_at) if existing else observation.observed_at
    return RuntimeSessionRecord(
        tenant_id=observation.tenant_id,
        session_id=observation.session_id,
        first_seen=first_seen,
        last_seen=last_seen,
        source=existing.source if existing and existing.source else observation.source,
        agent_name=existing.agent_name if existing and existing.agent_name else observation.agent_name,
        trace_id=existing.trace_id if existing and existing.trace_id else observation.trace_id,
        observation_count=(existing.observation_count if existing else 0) + 1,
        event_types=dict(sorted(event_types.items())),
        verdicts=dict(sorted(verdicts.items())),
        severities=dict(sorted(severities.items())),
        tools=sorted(tools)[:100],
    )


class InMemoryRuntimeEventStore:
    def __init__(self) -> None:
        self._observations: dict[tuple[str, str], RuntimeObservationRecord] = {}
        self._sessions: dict[tuple[str, str], RuntimeSessionRecord] = {}
        self._lock = threading.Lock()
        self._revisions: dict[tuple[str, str], list[RuntimeObservationRecord]] = {}
        self._trace_imports: dict[tuple[str, str], TraceImportCheckpoint] = {}

    def init_schema(self) -> None:
        """No-op: the in-memory backend has no persistent schema. Present so the
        in-memory store satisfies the shared
        :class:`agent_bom.storage.base.TenantScopedStore` contract."""

    def put_observation(self, record: RuntimeObservationRecord) -> None:
        self.put_observations_batch([record])

    def put_observations_batch(self, records: list[RuntimeObservationRecord]) -> int:
        unique_records = _dedupe_observation_records(records)
        if not unique_records:
            return 0
        with self._lock:
            return self._put_observations_locked(unique_records)

    def _put_observations_locked(self, unique_records: list[RuntimeObservationRecord]) -> int:
        new_records = [record for record in unique_records if (record.tenant_id, record.observation_id) not in self._observations]
        if not new_records:
            return 0
        existing_sessions: dict[str, RuntimeSessionRecord] = {
            record.session_id: session
            for record in new_records
            if (session := self._sessions.get((record.tenant_id, record.session_id))) is not None
        }
        merged_sessions = _merge_sessions_for_batch(existing_sessions, new_records)
        for record in new_records:
            self._observations[(record.tenant_id, record.observation_id)] = record
        for session_id, session in merged_sessions.items():
            self._sessions[(session.tenant_id, session_id)] = session
        for tenant_id in {record.tenant_id for record in new_records}:
            _enforce_in_memory_observation_cap(self._observations, tenant_id)
        return len(new_records)

    def get_trace_import(self, tenant_id: str, import_id: str) -> TraceImportCheckpoint | None:
        with self._lock:
            return self._trace_imports.get((tenant_id, import_id))

    def commit_trace_page(
        self, checkpoint: TraceImportCheckpoint, records: list[RuntimeObservationRecord], *, expected_revision: int
    ) -> TracePageCommit:
        validate_page(checkpoint, records, expected_revision)
        unique = _dedupe_observation_records(records)
        key = (checkpoint.tenant_id, checkpoint.import_id)
        with self._lock:
            check_revision(self._trace_imports.get(key), expected_revision, checkpoint)
            # Validate the whole page before changing any memory state.
            for record in unique:
                history = self._revisions.get((record.tenant_id, record.observation_id), [])
                old = self._observations.get((record.tenant_id, record.observation_id)) or (history[-1] if history else None)
                if record.surface == "imported_trace" and old and (old.surface != record.surface or old.session_id != record.session_id):
                    raise ValueError("Native span identity conflicts with retained evidence")
            updated = 0
            first_seen = []
            for record in unique:
                if record.surface != "imported_trace":
                    first_seen.append(record)
                    continue
                record_key = (record.tenant_id, record.observation_id)
                old = self._observations.get(record_key)
                history = self._revisions.setdefault(record_key, [old] if old else [])
                old = old or (history[-1] if history else None)
                if content_hash(record) in {content_hash(item) for item in history}:
                    continue
                history.append(record)
                if old:
                    if record_key in self._observations:
                        self._observations[record_key] = record
                    session_key = (record.tenant_id, record.session_id)
                    self._sessions[session_key] = revised_session(self._sessions[session_key], old, record)
                    updated += 1
                else:
                    first_seen.append(record)
            inserted = self._put_observations_locked(first_seen)
            self._trace_imports[key] = checkpoint
            return TracePageCommit(inserted, updated, len(unique) - inserted - updated)

    def list_observation_revisions(
        self, tenant_id: str, observation_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeObservationRecord]:
        with self._lock:
            return self._revisions.get((tenant_id, observation_id), [])[max(0, offset) : max(0, offset) + max(1, min(limit, 1000))]

    def query_observations(self, tenant_id: str, *, limit: int = 100, offset: int = 0, **filters: Any) -> dict[str, Any]:
        with self._lock:
            rows = [row for (owner, _), row in self._observations.items() if owner == tenant_id]
        return memory_observation_page(rows, limit=limit, offset=offset, **filters)

    def list_sessions(self, tenant_id: str, *, limit: int = 100, offset: int = 0) -> list[RuntimeSessionRecord]:
        with self._lock:
            rows = [row for (row_tenant, _), row in self._sessions.items() if row_tenant == tenant_id]
        return sorted(rows, key=lambda row: row.last_seen, reverse=True)[offset : offset + limit]

    def get_session(self, tenant_id: str, session_id: str) -> RuntimeSessionRecord | None:
        with self._lock:
            return self._sessions.get((tenant_id, session_id))

    def get_sessions(self, tenant_id: str, session_ids: list[str]) -> list[RuntimeSessionRecord]:
        keys = session_keys(session_ids)
        with self._lock:
            return [row for key in keys if (row := self._sessions.get((tenant_id, key))) is not None]

    def list_observations(
        self,
        tenant_id: str,
        *,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RuntimeObservationRecord]:
        with self._lock:
            rows = [
                row
                for (row_tenant, _), row in self._observations.items()
                if row_tenant == tenant_id and (session_id is None or row.session_id == session_id)
            ]
        return sorted(rows, key=lambda row: row.observed_at, reverse=True)[offset : offset + limit]


class SQLiteRuntimeEventStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def init_schema(self) -> None:
        """Idempotently (re)create this store's tables. Satisfies the shared
        :class:`agent_bom.storage.base.TenantScopedStore` contract."""
        self._init_db()

    def _init_db(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_observations (
                tenant_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, observation_id)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_sessions (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, session_id)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_runtime_observations_tenant_session_time "
            "ON runtime_observations(tenant_id, session_id, observed_at DESC)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_runtime_sessions_tenant_last_seen ON runtime_sessions(tenant_id, last_seen DESC)"
        )
        ensure_sqlite_gateway_activity_schema(self._conn)
        self._conn.execute(TRACE_IMPORT_TABLE_SQL)
        self._conn.execute(REVISION_TABLE_SQL)
        ensure_sqlite_schema_version(self._conn, "runtime_events", version=RUNTIME_TRACE_STORAGE_VERSION)
        self._conn.commit()

    def put_observation(self, record: RuntimeObservationRecord) -> None:
        self.put_observations_batch([record])

    def put_observations_batch(self, records: list[RuntimeObservationRecord]) -> int:
        unique_records = _dedupe_observation_records(records)
        if not unique_records:
            return 0
        conn = self._conn
        # Serialize the identity check and rollup with all SQLite writers. A
        # deferred transaction starts too late: competing readers can both
        # classify the same observation as new before either inserts it.
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            return self._put_observations_locked(conn, unique_records)

    def _put_observations_locked(self, conn: sqlite3.Connection, unique_records: list[RuntimeObservationRecord]) -> int:
        if not unique_records:
            return 0
        tenant_id = unique_records[0].tenant_id
        existing_ids: set[str] = set()
        observation_ids = [record.observation_id for record in unique_records]
        for offset in range(0, len(observation_ids), _BATCH_LOOKUP_CHUNK):
            chunk = observation_ids[offset : offset + _BATCH_LOOKUP_CHUNK]
            placeholders = ",".join("?" * len(chunk))
            rows = conn.execute(
                f"SELECT observation_id FROM runtime_observations WHERE tenant_id = ? AND observation_id IN ({placeholders})",  # nosec B608
                (tenant_id, *chunk),
            ).fetchall()
            existing_ids.update(row[0] for row in rows)
        new_records = [record for record in unique_records if record.observation_id not in existing_ids]
        if not new_records:
            return 0
        session_ids = sorted({record.session_id for record in new_records})
        existing_sessions: dict[str, RuntimeSessionRecord] = {}
        for offset in range(0, len(session_ids), _BATCH_LOOKUP_CHUNK):
            chunk = session_ids[offset : offset + _BATCH_LOOKUP_CHUNK]
            placeholders = ",".join("?" * len(chunk))
            rows = conn.execute(
                f"SELECT session_id, data FROM runtime_sessions WHERE tenant_id = ? AND session_id IN ({placeholders})",  # nosec B608
                (tenant_id, *chunk),
            ).fetchall()
            for session_id, data in rows:
                existing_sessions[session_id] = _session_from_json(data)
        merged_sessions = _merge_sessions_for_batch(existing_sessions, new_records)
        conn.executemany(
            """
            INSERT INTO runtime_observations
                (tenant_id, observation_id, session_id, observed_at, data)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    record.tenant_id,
                    record.observation_id,
                    record.session_id,
                    record.observed_at,
                    json.dumps(record.to_dict(), sort_keys=True),
                )
                for record in new_records
            ],
        )
        conn.executemany(
            """
            INSERT OR REPLACE INTO runtime_sessions
                (tenant_id, session_id, last_seen, data)
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    session.tenant_id,
                    session.session_id,
                    session.last_seen,
                    json.dumps(session.to_dict(), sort_keys=True),
                )
                for session in merged_sessions.values()
            ],
        )
        prune_runtime_observations_for_tenant(conn, tenant_id)
        return len(new_records)

    def get_trace_import(self, tenant_id: str, import_id: str) -> TraceImportCheckpoint | None:
        return read_checkpoint(self._conn, tenant_id, import_id)

    def commit_trace_page(
        self, checkpoint: TraceImportCheckpoint, records: list[RuntimeObservationRecord], *, expected_revision: int
    ) -> TracePageCommit:
        validate_page(checkpoint, records, expected_revision)
        unique = _dedupe_observation_records(records)
        conn = self._conn
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            check_revision(read_checkpoint(conn, checkpoint.tenant_id, checkpoint.import_id), expected_revision, checkpoint)
            updated, first_seen = reconcile_sql(conn, unique)
            inserted = self._put_observations_locked(conn, first_seen)
            write_checkpoint(conn, checkpoint)
            return TracePageCommit(inserted, updated, len(unique) - inserted - updated)

    def list_observation_revisions(
        self, tenant_id: str, observation_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeObservationRecord]:
        return read_revisions(self._conn, tenant_id, observation_id, limit=limit, offset=offset)

    def query_observations(self, tenant_id: str, *, limit: int = 100, offset: int = 0, **filters: Any) -> dict[str, Any]:
        return sql_observation_page(self._conn, tenant_id, limit=limit, offset=offset, **filters)

    def list_sessions(self, tenant_id: str, *, limit: int = 100, offset: int = 0) -> list[RuntimeSessionRecord]:
        rows = self._conn.execute(
            """
            SELECT data FROM runtime_sessions
            WHERE tenant_id = ?
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            (tenant_id, limit, offset),
        ).fetchall()
        return [_session_from_json(row[0]) for row in rows]

    def get_session(self, tenant_id: str, session_id: str) -> RuntimeSessionRecord | None:
        row = self._conn.execute(
            "SELECT data FROM runtime_sessions WHERE tenant_id = ? AND session_id = ?",
            (tenant_id, session_id),
        ).fetchone()
        return _session_from_json(row[0]) if row else None

    def get_sessions(self, tenant_id: str, session_ids: list[str]) -> list[RuntimeSessionRecord]:
        return sql_sessions(self._conn, tenant_id, session_ids)

    def list_observations(
        self,
        tenant_id: str,
        *,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RuntimeObservationRecord]:
        if session_id:
            rows = self._conn.execute(
                """
                SELECT data FROM runtime_observations
                WHERE tenant_id = ? AND session_id = ?
                ORDER BY observed_at DESC
                LIMIT ? OFFSET ?
                """,
                (tenant_id, session_id, limit, offset),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT data FROM runtime_observations
                WHERE tenant_id = ?
                ORDER BY observed_at DESC
                LIMIT ? OFFSET ?
                """,
                (tenant_id, limit, offset),
            ).fetchall()
        return [_observation_from_json(row[0]) for row in rows]


_RUNTIME_EVENT_STORE: RuntimeEventStore | None = None


def get_runtime_event_store() -> RuntimeEventStore:
    """Return the process runtime session/event store, durable by default.

    Selection (highest precedence first), via :mod:`agent_bom.api.durable_store`:
    - Postgres (``AGENT_BOM_POSTGRES_URL`` / ``AGENT_BOM_DB`` Postgres URL):
      multi-replica, tenant RLS — the runtime session timeline stays consistent
      across replicas.
    - in-memory (``AGENT_BOM_EPHEMERAL_STORE=1``): explicit opt-out; sessions
      and observations are lost on restart.
    - SQLite (default, or ``AGENT_BOM_DB`` file path): single-node durable —
      sessions survive a restart. This is the default.
    """
    global _RUNTIME_EVENT_STORE
    if _RUNTIME_EVENT_STORE is not None:
        return _RUNTIME_EVENT_STORE
    from agent_bom.storage.base import BackendKind
    from agent_bom.storage.factory import resolve_backend

    # mode="durable" preserves this store's durable-by-default ladder (the
    # behaviour the old durable_store.select_backend() gave): Postgres →
    # in-memory only on explicit ephemeral opt-out → durable SQLite default.
    selection = resolve_backend(mode="durable")
    if selection.backend is BackendKind.POSTGRES:
        from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore

        _RUNTIME_EVENT_STORE = PostgresRuntimeEventStore()
    elif selection.backend is BackendKind.MEMORY:
        _RUNTIME_EVENT_STORE = InMemoryRuntimeEventStore()
    else:
        _RUNTIME_EVENT_STORE = SQLiteRuntimeEventStore(selection.sqlite_path or "")
    return _RUNTIME_EVENT_STORE


def set_runtime_event_store(store: RuntimeEventStore | None) -> None:
    global _RUNTIME_EVENT_STORE
    _RUNTIME_EVENT_STORE = store


def reset_runtime_event_store() -> None:
    set_runtime_event_store(None)


def _enforce_in_memory_observation_cap(
    observations: dict[tuple[str, str], RuntimeObservationRecord],
    tenant_id: str,
) -> None:
    """Drop oldest in-memory observations for one tenant when over the cap."""
    from agent_bom.analytics_retention import analytics_max_events

    cap = analytics_max_events()
    if cap <= 0:
        return
    tenant_rows = [(key, row) for key, row in observations.items() if key[0] == tenant_id]
    if len(tenant_rows) <= cap:
        return
    tenant_rows.sort(key=lambda item: item[1].observed_at)
    for key, _row in tenant_rows[: len(tenant_rows) - cap]:
        observations.pop(key, None)
