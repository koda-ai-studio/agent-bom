"""Retained activity is filtered and counted before paging, within one tenant."""

import pytest

from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore, RuntimeObservationRecord, SQLiteRuntimeEventStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    store = InMemoryRuntimeEventStore() if request.param == "memory" else SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))
    for tenant in ["a", "b"]:
        store.put_observations_batch(
            [
                RuntimeObservationRecord(
                    tenant_id=tenant,
                    observation_id=str(i),
                    session_id="session",
                    observed_at=f"2026-10-12T00:00:0{i}Z",
                    source="langsmith" if i % 2 else "langfuse",
                    agent_name="same",
                    metadata={"connection_id": "connection" if i < 4 else "other"},
                )
                for i in range(6)
            ]
        )
    return store


def test_filter_and_totals_are_applied_before_the_page(store):
    page = store.query_observations("a", source="langsmith", connection_id="connection", limit=1, offset=0)
    assert page["total"] == 2
    assert [row.observation_id for row in page["observations"]] == ["3"]
    next_page = store.query_observations("a", source="langsmith", connection_id="connection", limit=1, offset=1)
    assert [row.observation_id for row in next_page["observations"]] == ["1"]
    assert page["sources"] == {"langsmith": 2}


@pytest.mark.parametrize(
    "filters", [{"session_id": "missing"}, {"agent_name": "sam"}, {"connection_id": "missing"}, {"source": "x' OR 1=1 --"}]
)
def test_exact_filters_cannot_widen_scope(store, filters):
    assert store.query_observations("a", **filters)["total"] == 0


def test_counts_do_not_include_another_tenant(store):
    assert store.query_observations("a")["total"] == 6
    assert store.query_observations("missing")["total"] == 0


def test_explorer_filters_before_paging_and_does_not_repeat_feed(store):
    from agent_bom.api.trace_explorer_read import assemble_trace_explorer

    result = assemble_trace_explorer(
        store,
        "a",
        limit=1,
        offset=1,
        source="langsmith",
        scan_id=None,
        feed={"events": [{"agent": "unrelated", "target": "feed-only"}]},
        finding_rows=[],
        graph_store=None,
    )
    assert result["retained_total"] == 3
    assert result["has_more"] is True
    assert result["source_counts"] == {"langsmith": 3}
    assert result["feed_included"] is False
    assert result["span_count"] == 1
    assert result["sessions"][0]["spans"][0]["span_id"] == "3"
