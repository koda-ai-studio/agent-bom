"""Local adoption milestones require successful scans, including across writers."""

import multiprocessing

from agent_bom.db.adoption_events import AdoptionEventStore


def test_failed_and_partial_scans_are_visible_but_do_not_claim_adoption(tmp_path):
    store = AdoptionEventStore(tmp_path / "events.db", enabled=True)
    for outcome in ("failed", "partial"):
        for channel in ("cli", "ci", "control_plane"):
            store.record("scan_completed", channel=channel, outcome=outcome)
    assert store.summary()["counts"] == {"scan_completed": 6}


def test_repeat_success_survives_reopening_the_store(tmp_path):
    path = tmp_path / "events.db"
    store = AdoptionEventStore(path, enabled=True)
    store.record("scan_completed", channel="cli", outcome="complete")
    store.record("scan_completed", channel="cli", outcome="failed")
    assert "repeat_use" not in store.summary()["counts"]
    reopened = AdoptionEventStore(path, enabled=True)
    reopened.record("scan_completed", channel="control_plane", outcome="complete")
    assert reopened.summary()["counts"] == {"scan_completed": 3, "repeat_use": 1, "control_plane_adopted": 1}


def test_summary_aggregates_without_loading_the_event_history(tmp_path, monkeypatch):
    store = AdoptionEventStore(tmp_path / "events.db", enabled=True)
    store.record("scan_completed", channel="cli", outcome="complete")
    monkeypatch.setattr(store, "events", lambda: (_ for _ in ()).throw(AssertionError("unbounded event materialization")))
    assert store.summary()["counts"] == {"scan_completed": 1}


def _concurrent_scan(path, barrier):
    original = AdoptionEventStore._insert

    def insert(self, conn, event, values):
        if event == "scan_completed":
            barrier.wait(timeout=20)
        return original(self, conn, event, values)

    AdoptionEventStore._insert = insert
    AdoptionEventStore(path, enabled=True).record("scan_completed", channel="cli", outcome="complete")


def test_concurrent_processes_record_the_second_success_exactly_once(tmp_path):
    path = tmp_path / "events.db"
    store = AdoptionEventStore(path, enabled=True)
    store.record("artifact_created", channel="cli", artifact_type="json")
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    processes = [context.Process(target=_concurrent_scan, args=(path, barrier)) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=30)
            assert process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
    assert store.summary()["counts"] == {"artifact_created": 1, "scan_completed": 2, "repeat_use": 1}
