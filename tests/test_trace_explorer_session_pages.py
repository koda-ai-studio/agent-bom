"""Observation pages retain exact tenant-scoped session metadata."""

import pytest

from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore, RuntimeObservationRecord, SQLiteRuntimeEventStore
from agent_bom.api.trace_explorer_read import assemble_trace_explorer


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return InMemoryRuntimeEventStore() if request.param == "memory" else SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))


def seed(store):
    for tenant in ("tenant-a", "tenant-b"):
        for index in range(5):
            store.put_observation(
                RuntimeObservationRecord(
                    tenant_id=tenant,
                    observation_id=f"observation-{index}",
                    session_id=f"session-{index}",
                    observed_at=f"2026-10-13T00:00:0{index}+00:00",
                    agent_name=tenant,
                )
            )


@pytest.mark.parametrize("filters,offset,expected", [({}, 2, ["session-2", "session-1"]), ({"session_id": "session-0"}, 0, ["session-0"])])
def test_later_and_filtered_observations_retain_session_details(store, filters, offset, expected):
    seed(store)
    payload = assemble_trace_explorer(
        store, "tenant-a", limit=2, offset=offset, scan_id=None, feed={}, finding_rows=[], graph_store=None, **filters
    )
    sessions = payload["sessions"]
    assert [row["session_id"] for row in sessions] == expected
    assert all(row["observation_count"] == 1 and row["first_seen"] and row["last_seen"] for row in sessions)


def test_bulk_sessions_are_bounded_exact_and_tenant_scoped(store):
    seed(store)
    statements = []
    if isinstance(store, SQLiteRuntimeEventStore):
        store._conn.set_trace_callback(statements.append)
    sessions = store.get_sessions("tenant-a", ["session-0", "session-2", "session-0", "missing"])
    assert {row.session_id for row in sessions} == {"session-0", "session-2"}
    assert all(row.tenant_id == row.agent_name == "tenant-a" for row in sessions)
    if statements:
        assert len([sql for sql in statements if sql.startswith("SELECT")]) == 1
    assert store.get_sessions("tenant-a", []) == []
    with pytest.raises(ValueError):
        store.get_sessions("tenant-a", [f"session-{index}" for index in range(501)])


def test_postgres_bulk_sessions_and_later_pages_respect_rls():
    import os
    from uuid import uuid4

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    tenants = ["session-page-" + uuid4().hex for _ in range(2)]
    with _new_application_pool(min_size=1, max_size=2) as pool:
        store = PostgresRuntimeEventStore(pool=pool)
        for tenant in tenants:
            with tenant_scope(tenant):
                for index in range(5):
                    store.put_observation(
                        RuntimeObservationRecord(tenant, f"o-{index}", f"s-{index}", f"2026-10-13T00:00:0{index}+00:00", agent_name=tenant)
                    )
        with tenant_scope(tenants[0]):
            sessions = store.get_sessions(tenants[0], ["s-0", "s-2", "s-0", "missing"])
            assert {row.session_id for row in sessions} == {"s-0", "s-2"}
            assert all(row.agent_name == tenants[0] for row in sessions)
            assert store.get_sessions(tenants[1], ["s-0"]) == []
            payload = assemble_trace_explorer(
                store, tenants[0], limit=2, offset=2, scan_id=None, feed={}, finding_rows=[], graph_store=None
            )
            assert [row["session_id"] for row in payload["sessions"]] == ["s-2", "s-1"]
            assert all(row["observation_count"] == 1 for row in payload["sessions"])


def test_bulk_sessions_order_is_deterministic_across_stores(store):
    seed(store)
    store.put_observation(
        RuntimeObservationRecord(
            tenant_id="tenant-a",
            observation_id="tie",
            session_id="session-z",
            observed_at="2026-10-13T00:00:04+00:00",
            agent_name="tenant-a",
        )
    )
    requested = ["session-1", "session-z", "session-3", "session-4", "session-0"]
    rows = store.get_sessions("tenant-a", requested)
    assert [row.session_id for row in rows] == ["session-z", "session-4", "session-3", "session-1", "session-0"]
    assert [row.session_id for row in store.get_sessions("tenant-a", list(reversed(requested)))] == [row.session_id for row in rows]
