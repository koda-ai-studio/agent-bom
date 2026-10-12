"""Lease-fenced collection pages sharing the runtime database transaction."""

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from agent_bom.api.runtime_event_store import RuntimeObservationRecord
from agent_bom.api.storage.sql import SqlBackend, SqlSession, require_tenant_id
from agent_bom.api.trace_collection.contracts import (
    LEASE_SECONDS,
    MAX_WINDOW_SECONDS,
    OVERLAP_SECONDS,
    CollectionConflictError,
    CollectionState,
)
from agent_bom.api.trace_collection.retry import retry_delay
from agent_bom.api.trace_collection.schema import CHECKPOINT_DDL, RECEIPT_DDL, RECEIPT_INDEX
from agent_bom.api.trace_collection.writes import put_page


class TraceCollectionStore:
    def __init__(self, backend: SqlBackend) -> None:
        self.backend = backend

    def init_schema(self) -> None:
        self.backend.bootstrap(
            "trace_collection", {"sqlite": [CHECKPOINT_DDL], "postgres": [CHECKPOINT_DDL]}, rls_table="trace_collection_checkpoints"
        )
        self.backend.bootstrap(
            "trace_collection",
            {"sqlite": [RECEIPT_DDL, RECEIPT_INDEX], "postgres": [RECEIPT_DDL, RECEIPT_INDEX]},
            rls_table="trace_collection_receipts",
        )

    def get(self, tenant: str, connection: str) -> CollectionState | None:
        require_tenant_id(tenant)
        with self.backend.transaction(read_only=True) as tx:
            return self._read(tx, tenant, connection)

    def _read(self, tx: SqlSession, tenant: str, connection: str, *, lock: bool = False) -> CollectionState | None:
        query = "SELECT data FROM trace_collection_checkpoints WHERE tenant_id=? AND connection_id=?"
        if lock and self.backend.dialect == "postgres":
            query = "SELECT data FROM trace_collection_checkpoints WHERE tenant_id=? AND connection_id=? FOR UPDATE"
        row = tx.execute(query, (tenant, connection)).fetchone()
        return CollectionState.model_validate_json(row[0]) if row else None

    def _begin(self, tx: SqlSession) -> None:
        if self.backend.dialect == "sqlite":
            tx.execute("BEGIN IMMEDIATE")

    def _clock(self, tx: SqlSession, supplied: float | None) -> float:
        if supplied is not None:
            return supplied
        query = (
            "SELECT EXTRACT(EPOCH FROM clock_timestamp())"
            if self.backend.dialect == "postgres"
            else "SELECT (julianday('now') - 2440587.5) * 86400"
        )
        return float(tx.execute(query).fetchone()[0])

    @staticmethod
    def _write(tx: SqlSession, tenant: str, connection: str, state: CollectionState) -> None:
        tx.execute(
            "UPDATE trace_collection_checkpoints SET data=? WHERE tenant_id=? AND connection_id=?",
            (state.model_dump_json(), tenant, connection),
        )

    def claim(self, tenant: str, connection: str, initial: CollectionState, *, now: float | None = None) -> CollectionState:
        require_tenant_id(tenant)
        with self.backend.transaction() as tx:
            self._begin(tx)
            tx.execute(
                "INSERT INTO trace_collection_checkpoints VALUES(?,?,?) ON CONFLICT(tenant_id,connection_id) DO NOTHING",
                (tenant, connection, initial.model_dump_json()),
            )
            state = self._read(tx, tenant, connection, lock=True)
            if state is None:
                raise CollectionConflictError("Collection checkpoint is unavailable.")
            now = self._clock(tx, now)
            if state.scope_digest != initial.scope_digest:
                raise CollectionConflictError("Connection scope changed; configure a new connection ID.")
            if max(state.lease_until, state.retry_after) > now:
                raise CollectionConflictError("Collection is busy or waiting to retry.")
            if state.completed_until and state.cursor is None:
                start = datetime.fromisoformat(state.completed_until) - timedelta(seconds=OVERLAP_SECONDS)
                end = min(datetime.fromisoformat(initial.window_end), start + timedelta(seconds=MAX_WINDOW_SECONDS))
                if end < datetime.fromisoformat(state.completed_until):
                    raise CollectionConflictError("Collection clock moved backwards; retry later.")
                state.window_start, state.window_end = start.isoformat(), end.isoformat()
                state.cursor_history = []
            state.owner, state.lease_until = uuid4().hex, now + LEASE_SECONDS
            state.status, state.last_error = "collecting", None
            self._write(tx, tenant, connection, state)
            return state

    def _owned(self, tx: SqlSession, tenant: str, connection: str, claimed: CollectionState, now: float | None) -> CollectionState:
        state = self._read(tx, tenant, connection, lock=True)
        now = self._clock(tx, now)
        if state is None or not claimed.owner or state.owner != claimed.owner or state.lease_until <= now:
            raise CollectionConflictError("Worker lease expired; checkpoint retained.")
        return state

    def commit(
        self,
        tenant: str,
        connection: str,
        claimed: CollectionState,
        records: list[RuntimeObservationRecord],
        *,
        next_cursor: str | None,
        now: float | None = None,
    ) -> CollectionState:
        require_tenant_id(tenant)
        with self.backend.transaction() as tx:
            self._begin(tx)
            if self.backend.dialect == "postgres":
                # Serialize with the runtime store's native-window importer as
                # well as other collection workers before reconciling history.
                tx.execute("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", (f"runtime_observations:{tenant}",))
            state = self._owned(tx, tenant, connection, claimed, now)
            now = self._clock(tx, now)
            native = [record for record in records if record.surface == "imported_trace"]
            projects = {record.metadata.get("project_id") for record in native}
            if native:
                if len(projects) != 1 or not all(isinstance(project, str) and project for project in projects):
                    raise CollectionConflictError("Collection requires one resolved native project.")
                project = str(next(iter(projects)))
                if state.project_id is not None and state.project_id != project:
                    raise CollectionConflictError("Native project changed; checkpoint retained.")
                if any(record.metadata.get("connection_id") != connection for record in native):
                    raise CollectionConflictError("Native connection changed; checkpoint retained.")
                state.project_id = project
            if next_cursor:
                cursor_digest = hashlib.sha256(next_cursor.encode()).hexdigest()
                if cursor_digest in state.cursor_history or len(state.cursor_history) >= 1000:
                    raise CollectionConflictError("Provider cursor cycle or page limit reached; checkpoint retained.")
                state.cursor_history.append(cursor_digest)
            state.consecutive_failures = 0
            state.persisted += put_page(tx, tenant, connection, records)
            state.cursor, state.pages = next_cursor, state.pages + 1
            state.last_success = datetime.fromtimestamp(now, timezone.utc).isoformat()
            state.owner, state.lease_until, state.retry_after = "", 0, 0
            state.status = "partial" if next_cursor else "caught_up"
            if next_cursor is None:
                state.completed_until = state.window_end
                floor = (datetime.fromisoformat(state.window_end) - timedelta(seconds=OVERLAP_SECONDS)).isoformat()
                tx.execute(
                    "DELETE FROM trace_collection_receipts WHERE tenant_id=? AND connection_id=? AND observed_at < ?",
                    (tenant, connection, floor),
                )
            self._write(tx, tenant, connection, state)
            return state

    def fail(
        self, tenant: str, connection: str, claimed: CollectionState, *, code: str, retry_after: float = 0, now: float | None = None
    ) -> CollectionState:
        require_tenant_id(tenant)
        with self.backend.transaction() as tx:
            self._begin(tx)
            state = self._owned(tx, tenant, connection, claimed, now)
            now = self._clock(tx, now)
            state.status, state.last_error = "failed", code
            state.consecutive_failures += 1
            state.owner, state.lease_until = "", 0
            state.retry_after = now + retry_delay(state.consecutive_failures, retry_after=retry_after)
            self._write(tx, tenant, connection, state)
            return state
