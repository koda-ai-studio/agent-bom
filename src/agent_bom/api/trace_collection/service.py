"""Bounded manual collection with credential revalidation and safe failure receipts."""

import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from threading import Lock

from fastapi import HTTPException

from agent_bom.api.audit_log import log_action
from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore
from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore, get_runtime_event_store
from agent_bom.api.storage.sql import PostgresBackend, SqlBackend, SQLiteBackend
from agent_bom.api.trace_collection.contracts import (
    MAX_WINDOW_SECONDS,
    SAFETY_DELAY_SECONDS,
    CollectionConflictError,
    CollectionReceipt,
    CollectionState,
    receipt,
)
from agent_bom.api.trace_collection.langfuse import ProviderFailureError, fetch_page, identity
from agent_bom.api.trace_collection.store import TraceCollectionStore
from agent_bom.api.trace_connection_broker import pull_credentials

_store_lock = Lock()


def collection_store() -> TraceCollectionStore:
    runtime = get_runtime_event_store()
    if not isinstance(runtime, (SQLiteRuntimeEventStore, PostgresRuntimeEventStore)):
        raise HTTPException(status_code=503, detail="Trace collection requires durable runtime storage.")
    # Serialize initialization only; page HTTP and SQL work never hold this lock.
    with _store_lock:
        return _initialized_store(runtime)


@lru_cache(maxsize=1)
def _initialized_store(runtime: SQLiteRuntimeEventStore | PostgresRuntimeEventStore) -> TraceCollectionStore:
    backend: SqlBackend
    if isinstance(runtime, SQLiteRuntimeEventStore):
        backend = SQLiteBackend(runtime._db_path, connection_factory=lambda: runtime._conn)
    else:
        backend = PostgresBackend(runtime._pool)
    store = TraceCollectionStore(backend)
    store.init_schema()
    return store


def scope(credentials: dict[str, str]) -> str:
    optional = tuple(credentials.get(key, "") for key in ("project", "scope_account_id", "scope_environment", "scope_cloud_provider"))
    # Preserve published checkpoints when no new scope binding is configured.
    # Adding any binding changes identity and must still fail closed.
    return identity(credentials["host"].rstrip("/"), credentials["public_key"], *(optional if any(optional) else ()))


def initial_state(credentials: dict[str, str], now: float) -> CollectionState:
    end = datetime.fromtimestamp(now, timezone.utc) - timedelta(seconds=SAFETY_DELAY_SECONDS)
    return CollectionState(
        scope_digest=scope(credentials), window_start=(end - timedelta(seconds=MAX_WINDOW_SECONDS)).isoformat(), window_end=end.isoformat()
    )


def collect(tenant: str, connection: str, *, actor: str) -> CollectionReceipt:
    credentials = pull_credentials(tenant, "langfuse", {"connection_id": connection}, actor=actor)
    store = collection_store()
    state = store.claim(tenant, connection, initial_state(credentials, time.time()))
    try:
        records, cursor = fetch_page(tenant, connection, credentials, state)
        current = pull_credentials(tenant, "langfuse", {"connection_id": connection}, actor=actor)
        if scope(current) != state.scope_digest:
            raise CollectionConflictError("Connection scope changed during collection.")
        state = store.commit(tenant, connection, state, records, next_cursor=cursor)
    except (ProviderFailureError, CollectionConflictError, HTTPException) as exc:
        code = exc.code if isinstance(exc, ProviderFailureError) else "connection_or_evidence_conflict"
        try:
            state = store.fail(
                tenant, connection, state, code=code, retry_after=exc.retry_after if isinstance(exc, ProviderFailureError) else 0
            )
        except CollectionConflictError:
            raise CollectionConflictError("Collection lease expired; retry from the saved checkpoint.") from exc
    log_action(
        "trace_collection.page",
        actor=actor,
        tenant_id=tenant,
        resource=f"trace_connection/{connection}",
        status=state.status,
        error_code=state.last_error,
        pages=state.pages,
        persisted=state.persisted,
    )
    return receipt(connection, state, time.time())


def status(tenant: str, connection: str, *, actor: str) -> CollectionReceipt:
    credentials = pull_credentials(tenant, "langfuse", {"connection_id": connection}, actor=actor)
    state = collection_store().get(tenant, connection)
    if state is not None and state.scope_digest != scope(credentials):
        raise CollectionConflictError("Connection scope changed; configure a new connection ID.")
    return receipt(connection, state, time.time())
