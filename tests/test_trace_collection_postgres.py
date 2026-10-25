"""Real application-role PostgreSQL contract; migrations own DDL and RLS."""

import os
from dataclasses import replace
from uuid import uuid4

import pytest

from agent_bom.api.postgres_common import _new_application_pool, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore
from agent_bom.api.runtime_event_store import RuntimeObservationRecord
from agent_bom.api.storage.sql import PostgresBackend
from agent_bom.api.trace_collection.contracts import CollectionConflictError, CollectionState
from agent_bom.api.trace_collection.store import TraceCollectionStore

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires migrated private PostgreSQL")


def test_postgres_window_filters_before_budget_and_enforces_application_rls(monkeypatch):
    from agent_bom.api.trace_collection import normalized_events as reads
    from agent_bom.runtime.normalized_trace import NormalizedTraceEvent

    tenant = "trace-window-" + uuid4().hex
    token = set_current_tenant(tenant)
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        runtime = PostgresRuntimeEventStore(pool)
        with pool.connection() as conn:
            assert conn.execute("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone() == (False,)
        for identity, stamp in [
            ("new", "2026-10-25T00:00:00Z"),
            ("a", "2026-10-19T20:00:00-04:00"),
            ("b", "2026-10-20T00:00:00Z"),
            ("c", "2026-10-20T00:00:00Z"),
        ]:
            runtime.put_observation(
                reads._record(
                    NormalizedTraceEvent(
                        tenant_id=tenant, source="otel", source_trace_id="trace", source_span_id=identity, started_at=stamp
                    )
                )
            )
        monkeypatch.setattr(reads, "MAX_WINDOW_EVENTS", 2)
        monkeypatch.setattr(reads, "_PAGE", 1)
        events, limited = reads.load_window_events(runtime, tenant, window_start="2026-10-10T00:00:00Z", window_end="2026-10-20T00:00:00Z")
        assert len(events) == 2 and limited
        assert all(event["source_span_id"] != "new" for event in events)
        other = set_current_tenant(tenant + "-other")
        try:
            assert (
                runtime.window_observations(
                    tenant, window_start="2026-10-10T00:00:00Z", window_end="2026-10-20T00:00:00Z", surfaces=(reads.NORMALIZED_SURFACE,)
                )
                == []
            )
        finally:
            reset_current_tenant(other)
    finally:
        pool.close()
        reset_current_tenant(token)


def test_postgres_atomic_restart_replay_fencing_and_rls():
    tenant = "trace-test-" + uuid4().hex
    token = set_current_tenant(tenant)
    pool = _new_application_pool(min_size=1, max_size=3)
    try:
        runtime = PostgresRuntimeEventStore(pool)
        backend = PostgresBackend(pool)
        store = TraceCollectionStore(backend)
        store.init_schema()
        initial = CollectionState(scope_digest="project", window_start="2026-10-10T00:00:00+00:00", window_end="2026-10-11T00:00:00+00:00")
        record = RuntimeObservationRecord(tenant, "event", "session", "2026-10-10T23:55:00+00:00", tool_name="read")
        claimed = store.claim(tenant, "production", initial, now=100)
        store.commit(tenant, "production", claimed, [record], next_cursor="page-2", now=101)
        restarted = TraceCollectionStore(PostgresBackend(pool))
        claimed = restarted.claim(tenant, "production", initial, now=102)
        with pytest.raises(CollectionConflictError):
            restarted.commit(
                tenant,
                "production",
                claimed,
                [replace(record, observation_id="new"), replace(record, tool_name="write")],
                next_cursor=None,
                now=103,
            )
        assert len(runtime.list_observations(tenant)) == 1
        assert restarted.get(tenant, "production").cursor == "page-2"
        replacement = store.claim(tenant, "production", initial, now=200)
        with pytest.raises(CollectionConflictError):
            restarted.commit(tenant, "production", claimed, [record], next_cursor=None, now=201)
        done = store.commit(tenant, "production", replacement, [record], next_cursor=None, now=202)
        assert done.persisted == 1
        assert runtime.get_session(tenant, "session").observation_count == 1
        other = set_current_tenant(tenant + "-other")
        try:
            assert store.get(tenant, "production") is None  # SQL predicate alone cannot bypass RLS
            assert runtime.list_observations(tenant) == []
        finally:
            reset_current_tenant(other)
    finally:
        pool.close()
        reset_current_tenant(token)


@pytest.mark.parametrize("count", [1, 201])
def test_postgres_window_import_and_collection_share_native_identity_under_concurrency(count):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page
    from agent_bom.api.storage.runtime_trace_imports import TraceImportCheckpoint

    tenant = "trace-native-" + uuid4().hex
    token = set_current_tenant(tenant)
    pool = _new_application_pool(min_size=1, max_size=4)
    try:
        runtime = PostgresRuntimeEventStore(pool)
        collection = TraceCollectionStore(PostgresBackend(pool))
        collection.init_schema()
        initial = CollectionState(scope_digest="project", window_start="2026-10-10T00:00:00+00:00", window_end="2026-10-11T00:00:00+00:00")
        claimed = collection.claim(tenant, "production", initial, now=100)
        records = prepare_trace_page(
            {"spans": [{"spanId": f"native-span-{index}", "traceId": "native-trace", "attributes": []} for index in range(count)]},
            scope=TraceImportScope(tenant, "langfuse", "production", "https://example.test", "project"),
            collected_at="2026-10-12T00:00:00+00:00",
        ).observations
        checkpoint = TraceImportCheckpoint(
            tenant, "window", 1, initial.window_start, initial.window_end, "2026-10-12T00:00:00+00:00", complete=True
        )
        barrier = Barrier(2)

        def write(manual):
            active = set_current_tenant(tenant)
            try:
                barrier.wait(timeout=10)
                if manual:
                    return runtime.commit_trace_page(checkpoint, records, expected_revision=0).inserted
                return collection.commit(tenant, "production", claimed, records, next_cursor=None, now=101).persisted
            finally:
                reset_current_tenant(active)

        with ThreadPoolExecutor(max_workers=2) as workers:
            counts = list(workers.map(write, (True, False)))
        assert sum(counts) == count
        assert len(runtime.list_observations(tenant, limit=500)) == count
        assert len(runtime.list_observation_revisions(tenant, records[0].observation_id)) == 1
        assert len(runtime.list_observation_revisions(tenant, records[-1].observation_id)) == 1
        assert runtime.get_session(tenant, records[0].session_id).observation_count == count
    finally:
        pool.close()
        reset_current_tenant(token)
