"""Runtime import batches must preserve tenant boundaries and concurrent counts."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore, RuntimeObservationRecord, SQLiteRuntimeEventStore


def record(index=0):
    return RuntimeObservationRecord(
        tenant_id="tenant-a", observation_id=f"span-{index}", session_id="session", observed_at="2026-10-11T12:00:00Z"
    )


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_mixed_tenant_batch_fails_without_partial_write(backend, tmp_path):
    store = InMemoryRuntimeEventStore() if backend == "memory" else SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))
    with pytest.raises(ValueError, match="tenant"):
        store.put_observations_batch([record(), replace(record(1), tenant_id="tenant-b")])
    assert store.list_observations("tenant-a") == []
    assert store.list_observations("tenant-b") == []
    assert store.list_sessions("tenant-a") == []
    assert store.list_sessions("tenant-b") == []


def test_sqlite_parallel_replays_keep_exact_session_count(tmp_path):
    path = str(tmp_path / "runtime.db")
    store = SQLiteRuntimeEventStore(path)
    stores = [SQLiteRuntimeEventStore(path) for _ in range(4)]
    ready = Barrier(4)

    def write(index):
        ready.wait(timeout=5)
        return stores[index].put_observations_batch([record(i) for i in range(20)])

    with ThreadPoolExecutor(max_workers=4) as pool:
        inserted = list(pool.map(write, range(4)))
    assert sum(inserted) == 20
    assert len(store.list_observations("tenant-a")) == 20
    assert store.get_session("tenant-a", "session").observation_count == 20


def test_runtime_batch_redaction_reuses_field_values_without_cross_batch_state(monkeypatch):
    from agent_bom.api.routes import observability
    from agent_bom.api.storage import runtime_records
    from agent_bom.redaction import payload

    store = InMemoryRuntimeEventStore()
    monkeypatch.setattr(observability, "get_runtime_event_store", lambda: store)
    real = payload.sanitize_string
    real_text = observability.sanitize_text
    text_calls = []
    calls = []

    def text(value, max_len=1000):
        text_calls.append((value, max_len))
        return real_text(value, max_len=max_len)

    monkeypatch.setattr(observability, "sanitize_text", text)
    monkeypatch.setattr(runtime_records, "sanitize_text", text)

    def sanitize(value, key, max_str_len):
        calls.append((value, key))
        return real(value, key, max_str_len)

    monkeypatch.setattr(payload, "sanitize_string", sanitize)
    events = [
        {
            "event_id": f"batch-{i}",
            "session_id": "session",
            "agent_name": "shared-agent",
            "message": "shared-message",
            "metadata": {"label": "shared-label", "authorization": "shared-label"},
        }
        for i in range(50)
    ]
    assert observability._persist_runtime_observations(events, tenant_id="tenant-a") == 50
    assert calls.count(("shared-label", "label")) == 1
    assert calls.count(("shared-message", "message")) == 1
    assert text_calls.count(("shared-agent", 200)) == 1
    assert calls.count(("shared-label", "authorization")) == 1
    rows = store.list_observations("tenant-a")
    assert all(row.metadata["label"] == "shared-label" and row.metadata["authorization"] != "shared-label" for row in rows)
    rows[0].metadata["label"] = "mutated"
    assert rows[1].metadata["label"] == "shared-label"
    calls.clear()
    text_calls.clear()
    assert observability._persist_runtime_observations(events[:1], tenant_id="tenant-b") == 1
    assert calls.count(("shared-label", "label")) == 1, "cache must not retain data across batches or tenants"
    assert text_calls.count(("shared-agent", 200)) == 1
