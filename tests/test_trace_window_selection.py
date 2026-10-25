"""Historical graph windows apply bounds before consuming the event budget."""

from dataclasses import replace

import pytest

from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore, SQLiteRuntimeEventStore
from agent_bom.api.trace_collection import normalized_events as reads
from agent_bom.runtime.normalized_trace import NormalizedTraceEvent

START = "2026-10-10T00:00:00+00:00"
END = "2026-10-20T00:00:00+00:00"


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return InMemoryRuntimeEventStore() if request.param == "memory" else SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))


def add(store, identity, timestamp, *, tenant="a", surface=reads.NORMALIZED_SURFACE):
    event = NormalizedTraceEvent(tenant_id=tenant, source="otel", source_trace_id="trace", source_span_id=identity, started_at=timestamp)
    record = replace(reads._record(event), surface=surface)
    store.put_observation(record)


def test_newer_observations_cannot_starve_a_historical_window(store, monkeypatch):
    monkeypatch.setattr(reads, "MAX_WINDOW_EVENTS", 2)
    for i in range(3):
        add(store, str(i), "2026-10-25T00:00:00+00:00")
    add(store, "wanted", "2026-10-15T00:00:00+00:00")
    events, limited = reads.load_window_events(store, "a", window_start=START, window_end=END)
    assert [event["source_span_id"] for event in events] == ["wanted"]
    assert limited is False


def test_window_bounds_are_inclusive_and_utc_equivalent(store):
    add(store, "start", "2026-10-10T00:00:00Z")
    add(store, "end", "2026-10-19T20:00:00-04:00")
    add(store, "too-new", "2026-10-20T00:00:00.000001+00:00")
    add(store, "too-old", "2026-10-09T23:59:59.999999+00:00")
    add(store, "other-tenant", "2026-10-15T00:00:00Z", tenant="b")
    events, limited = reads.load_window_events(store, "a", window_start=START, window_end=END)
    assert {event["source_span_id"] for event in events} == {"start", "end"}
    assert limited is False


def test_tied_timestamps_page_without_loss_and_all_surfaces_share_the_budget(store, monkeypatch):
    monkeypatch.setattr(reads, "_PAGE", 2)
    for i in range(5):
        add(store, str(i), "2026-10-15T00:00:00Z", surface=reads.IMPORTED_SURFACE if i % 2 else reads.NORMALIZED_SURFACE)
    events, limited = reads.load_window_events(store, "a", window_start=START, window_end=END)
    assert len(events) == len({event["source_span_id"] for event in events}) == 5
    assert limited is False
    monkeypatch.setattr(reads, "MAX_WINDOW_EVENTS", 3)
    events, limited = reads.load_window_events(store, "a", window_start=START, window_end=END)
    assert len(events) == 3
    assert limited is True


def test_sql_window_does_not_repeat_count_queries_or_use_offset(tmp_path, monkeypatch):
    store = SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))
    monkeypatch.setattr(reads, "_PAGE", 1)
    for i in range(3):
        add(store, str(i), "2026-10-15T00:00:00Z")
    statements = []
    store._conn.set_trace_callback(statements.append)
    events, _ = reads.load_window_events(store, "a", window_start=START, window_end=END)
    assert len(events) == 3
    assert not any("OFFSET" in sql.upper() or "COUNT(" in sql.upper() for sql in statements)
