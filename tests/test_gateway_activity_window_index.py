"""Window paging must use UTC time indexes without scanning retained events."""

from concurrent.futures import ThreadPoolExecutor

from agent_bom.api.gateway_activity_store import SQLiteGatewayActivityStore
from agent_bom.api.storage.runtime_observation_window import epoch_us
from tests.test_persisted_runtime_graph import END, START, _gateway


def test_window_read_does_not_convert_every_retained_timestamp(tmp_path, monkeypatch):
    store = SQLiteGatewayActivityStore(str(tmp_path / "ledger.db"))
    store.append_batch([_gateway(f"event-{i:04d}") for i in range(500)])
    converted = []

    def measured(value):
        converted.append(value)
        return epoch_us(value)

    monkeypatch.setattr("agent_bom.api.storage.gateway_activity_window.epoch_us", measured)
    store._conn.create_function("agent_bom_epoch_us", 1, measured, deterministic=True)
    first = store.window_activity("tenant-a", window_start=START, window_end=END, limit=10)
    assert [row.event_id for row in first] == [f"event-{i:04d}" for i in range(499, 489, -1)]
    assert len(converted) <= 10, "page reads must seek the index rather than convert the tenant history"


def test_index_reopens_and_thread_writes_preserve_offset_microseconds(tmp_path):
    path = str(tmp_path / "ledger.db")
    store = SQLiteGatewayActivityStore(path)
    store.append_batch(
        [
            _gateway("a", "2026-10-15T00:00:00.000001Z"),
            _gateway("b", "2026-10-14T20:00:00.000001-04:00"),
            _gateway("c", "2026-10-15T00:00:00.000002Z"),
        ]
    )
    store._conn.execute("DROP INDEX idx_gateway_activity_window")
    store._conn.commit()
    store = SQLiteGatewayActivityStore(path)
    with ThreadPoolExecutor(max_workers=1) as workers:
        workers.submit(store.append_batch, [_gateway("foreign", tenant="other")]).result()
    first = store.window_activity("tenant-a", window_start=START, window_end=END, limit=2)
    assert [row.event_id for row in first] == ["c", "b"]
    second = store.window_activity(
        "tenant-a", window_start=START, window_end=END, limit=2, before=(first[-1].event_timestamp, first[-1].event_id)
    )
    assert [row.event_id for row in second] == ["a"]
