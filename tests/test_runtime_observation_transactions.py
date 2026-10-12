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
