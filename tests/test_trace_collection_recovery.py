"""Process death and lost acknowledgments exercise real transaction boundaries."""

import os
import subprocess
import sys
from uuid import uuid4

import pytest

from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.runtime_event_store import RuntimeObservationRecord, SQLiteRuntimeEventStore
from agent_bom.api.storage.sql import PostgresBackend, SQLiteBackend
from agent_bom.api.trace_collection.contracts import CollectionState
from agent_bom.api.trace_collection.store import TraceCollectionStore


def open_stores(kind, path):
    if kind == "sqlite":
        runtime = SQLiteRuntimeEventStore(path)
        return runtime, TraceCollectionStore(SQLiteBackend(path)), None
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore

    pool = _new_application_pool(min_size=1, max_size=2)
    return PostgresRuntimeEventStore(pool), TraceCollectionStore(PostgresBackend(pool)), pool


def sample(tenant):
    return RuntimeObservationRecord(tenant, "event-1", "session-1", "2026-10-10T23:55:00+00:00", tool_name="read")


@pytest.mark.parametrize(
    "kind",
    [
        "sqlite",
        pytest.param(
            "postgres", marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")
        ),
    ],
)
@pytest.mark.parametrize("point", ["before_commit", "lost_ack"])
def test_process_death_preserves_atomic_page(kind, point, tmp_path):
    tenant = "trace-crash-" + uuid4().hex
    token = set_current_tenant(tenant)
    path = str(tmp_path / "runtime.db")
    runtime, store, pool = open_stores(kind, path)
    try:
        store.init_schema()
        initial = CollectionState(scope_digest="scope", window_start="2026-10-10T00:00:00+00:00", window_end="2026-10-11T00:00:00+00:00")
        store.claim(tenant, "production", initial, now=100)
        code = """
import os,sys
from tests.test_trace_collection_recovery import open_stores,sample
from agent_bom.api.postgres_common import set_current_tenant
kind,path,tenant,point = sys.argv[1:]
set_current_tenant(tenant)
runtime,store,pool=open_stores(kind,path)
state=store.get(tenant,"production")
if point == "before_commit":
    store._write = lambda *args: os._exit(73)
store.commit(tenant,"production",state,[sample(tenant)],next_cursor="next",now=101)
os._exit(74)
"""
        child = subprocess.run([sys.executable, "-c", code, kind, path, tenant, point], capture_output=True, timeout=30)
        assert child.returncode == (73 if point == "before_commit" else 74), child.stderr.decode()
        assert len(runtime.list_observations(tenant)) == (0 if point == "before_commit" else 1)
        assert store.get(tenant, "production").cursor == (None if point == "before_commit" else "next")
        recovered = store.claim(tenant, "production", initial, now=200)
        done = store.commit(tenant, "production", recovered, [sample(tenant)], next_cursor=None, now=201)
        assert done.persisted == 1
        assert runtime.get_session(tenant, "session-1").observation_count == 1
    finally:
        if pool:
            pool.close()
        reset_current_tenant(token)


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")
def test_database_disconnect_rolls_back_page_and_checkpoint(tmp_path, monkeypatch):
    import psycopg

    tenant = "trace-disconnect-" + uuid4().hex
    token = set_current_tenant(tenant)
    runtime, store, pool = open_stores("postgres", str(tmp_path))
    try:
        store.init_schema()
        initial = CollectionState(scope_digest="scope", window_start="2026-10-10T00:00:00+00:00", window_end="2026-10-11T00:00:00+00:00")
        claimed = store.claim(tenant, "production", initial, now=100)

        def disconnect(tx, *args):
            tx.execute("SELECT pg_terminate_backend(pg_backend_pid())")

        with monkeypatch.context() as patch:
            patch.setattr(store, "_write", disconnect)
            with pytest.raises(psycopg.Error):
                store.commit(tenant, "production", claimed, [sample(tenant)], next_cursor="next", now=101)
        assert not runtime.list_observations(tenant)
        assert store.get(tenant, "production").cursor is None
        recovered = store.claim(tenant, "production", initial, now=200)
        assert store.commit(tenant, "production", recovered, [sample(tenant)], next_cursor=None, now=201).persisted == 1
    finally:
        pool.close()
        reset_current_tenant(token)


@pytest.mark.parametrize(
    "kind",
    [
        "sqlite",
        pytest.param(
            "postgres", marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")
        ),
    ],
)
def test_concurrent_claims_elect_one_owner(kind, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from agent_bom.api.trace_collection.contracts import CollectionConflictError

    tenant = "trace-race-" + uuid4().hex
    token = set_current_tenant(tenant)
    runtime, store, pool = open_stores(kind, str(tmp_path / "runtime.db"))
    initial = CollectionState(scope_digest="scope", window_start="2026-10-10T00:00:00+00:00", window_end="2026-10-11T00:00:00+00:00")
    barrier = Barrier(8)

    def claim():
        worker_token = set_current_tenant(tenant)
        try:
            barrier.wait(timeout=10)
            try:
                return store.claim(tenant, "production", initial, now=100)
            except CollectionConflictError:
                return None
        finally:
            reset_current_tenant(worker_token)

    try:
        store.init_schema()
        with ThreadPoolExecutor(max_workers=8) as executor:
            winners = [state for state in executor.map(lambda _: claim(), range(8)) if state is not None]
        assert len(winners) == 1
        store.commit(tenant, "production", winners[0], [sample(tenant)], next_cursor=None, now=101)
        assert runtime.get_session(tenant, "session-1").observation_count == 1
    finally:
        if pool:
            pool.close()
        reset_current_tenant(token)
