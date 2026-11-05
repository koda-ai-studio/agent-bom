"""Job-adapter transactions for projected finding history."""

from contextlib import contextmanager
from typing import Any

from agent_bom.api.postgres_common import _tenant_connection
from agent_bom.api.storage.finding_history import HistoryReader, backfill_history
from agent_bom.api.storage.finding_lifecycle import unbackfilled_tenants
from agent_bom.api.storage.sql import connection_session, require_tenant_id
from agent_bom.api.tenant_worker import tenant_bound_context


@contextmanager
def sqlite_history_read(store: Any, tenant_id: str):
    require_tenant_id(tenant_id)
    conn = store._conn
    if conn.in_transaction:
        raise ValueError("finding history requires an idle connection")
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        yield HistoryReader(connection_session(conn, "sqlite"), "sqlite", tenant_id)
    finally:
        conn.rollback()
        conn.execute("PRAGMA query_only=OFF")
        store._close_thread_connection()


def sqlite_history_backfill(store: Any, tenant_id: str, job_ids: list[str]) -> int:
    require_tenant_id(tenant_id)
    try:
        store._conn.execute("BEGIN IMMEDIATE")
        count = backfill_history(connection_session(store._conn, "sqlite"), "sqlite", tenant_id, job_ids)
        store._conn.commit()
        return count
    except Exception:
        store._conn.rollback()
        raise
    finally:
        store._close_thread_connection()


@contextmanager
def postgres_history_read(store: Any, tenant_id: str):
    require_tenant_id(tenant_id)
    with _tenant_connection(store._pool, repeatable_read=True) as conn:
        yield HistoryReader(connection_session(conn, "postgres"), "postgres", tenant_id)


def postgres_history_backfill(store: Any, tenant_id: str, job_ids: list[str]) -> int:
    require_tenant_id(tenant_id)
    with _tenant_connection(store._pool) as conn:
        count = backfill_history(connection_session(conn, "postgres"), "postgres", tenant_id, job_ids)
        conn.commit()
        return count


@contextmanager
def sqlite_lifecycle_session(store: Any, tenant_id: str, *, write: bool = True):
    """One committed transaction on the finding lifecycle tables; a read takes no writer lock."""
    require_tenant_id(tenant_id)
    conn = store._conn
    try:
        with conn:  # commits on success, rolls back on an exception
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield connection_session(conn, "sqlite")
    finally:
        store._close_thread_connection()


@contextmanager
def postgres_lifecycle_session(store: Any, tenant_id: str, *, write: bool = True):
    require_tenant_id(tenant_id)
    with tenant_bound_context(tenant_id), _tenant_connection(store._pool) as conn:
        yield connection_session(conn, "postgres")
        conn.commit()


def sqlite_unbackfilled_tenants(store: Any, limit: int) -> list[str]:
    try:
        return unbackfilled_tenants(connection_session(store._conn, "sqlite"), "sqlite", limit)
    finally:
        store._close_thread_connection()


def postgres_unbackfilled_tenants(store: Any, limit: int) -> list[str]:
    with store._scope_connection(all_tenants=True) as conn:
        return unbackfilled_tenants(connection_session(conn, "postgres"), "postgres", limit)


class PostgresFindingLifecycle:
    """The job store's finding lifecycle surface."""

    finding_lifecycle_dialect = "postgres"
    finding_lifecycle_session = postgres_lifecycle_session
    finding_lifecycle_unbackfilled_tenants = postgres_unbackfilled_tenants
