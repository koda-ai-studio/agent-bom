"""Observation pages and resume checkpoints commit as one tenant-scoped unit."""

from dataclasses import replace

import pytest

from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore, RuntimeObservationRecord, SQLiteRuntimeEventStore
from agent_bom.api.storage.runtime_trace_imports import TraceImportCheckpoint, TraceImportConflictError


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return InMemoryRuntimeEventStore() if request.param == "memory" else SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))


def checkpoint(revision=1):
    return TraceImportCheckpoint(
        tenant_id="tenant",
        import_id="source",
        revision=revision,
        window_start="2026-10-11T00:00:00Z",
        window_end="2026-10-12T00:00:00Z",
        cursor="next-page",
        updated_at="2026-10-12T00:00:01Z",
    )


def observation(identity="span"):
    return RuntimeObservationRecord(tenant_id="tenant", observation_id=identity, session_id="trace", observed_at="2026-10-11T12:00:00Z")


def test_commit_page_advances_only_the_expected_revision(store):
    assert store.get_trace_import("tenant", "source") is None
    assert store.commit_trace_page(checkpoint(), [observation()], expected_revision=0).inserted == 1
    assert store.get_trace_import("tenant", "source").cursor == "next-page"
    with pytest.raises(TraceImportConflictError):
        store.commit_trace_page(checkpoint(), [observation("uncommitted")], expected_revision=0)
    assert [row.observation_id for row in store.list_observations("tenant")] == ["span"]
    assert store.get_trace_import("tenant", "source").revision == 1
    assert store.get_trace_import("other-tenant", "source") is None
    complete = replace(checkpoint(2), cursor=None, complete=True)
    assert store.commit_trace_page(complete, [observation()], expected_revision=1).inserted == 0
    assert store.get_trace_import("tenant", "source").complete is True
    assert store.get_session("tenant", "trace").observation_count == 1


def test_invalid_page_never_advances_checkpoint(store):
    with pytest.raises(ValueError, match="tenant"):
        store.commit_trace_page(checkpoint(), [replace(observation(), tenant_id="other")], expected_revision=0)
    assert store.get_trace_import("tenant", "source") is None
    assert store.list_observations("other") == []


def test_empty_page_can_record_completion_without_fabricated_observations(store):
    complete = replace(checkpoint(), cursor=None, complete=True)
    assert store.commit_trace_page(complete, [], expected_revision=0).inserted == 0
    assert store.get_trace_import("tenant", "source").complete is True
    assert store.list_sessions("tenant") == []


def test_sqlite_checkpoint_survives_restart(tmp_path):
    path = str(tmp_path / "runtime.db")
    first = SQLiteRuntimeEventStore(path)
    first.commit_trace_page(checkpoint(), [observation()], expected_revision=0)
    second = SQLiteRuntimeEventStore(path)
    assert second.get_trace_import("tenant", "source") == checkpoint()
    assert len(second.list_observations("tenant")) == 1


def test_checkpoint_write_failure_rolls_back_the_entire_sqlite_page(tmp_path, monkeypatch):
    from agent_bom.api import runtime_event_store

    store = SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))

    def fail_write(*_args, **_kwargs):
        raise RuntimeError("injected checkpoint failure")

    with monkeypatch.context() as patch:
        patch.setattr(runtime_event_store, "write_checkpoint", fail_write)
        with pytest.raises(RuntimeError, match="injected"):
            store.commit_trace_page(checkpoint(), [observation()], expected_revision=0)
    assert store.get_trace_import("tenant", "source") is None
    assert store.list_observations("tenant") == []
    assert store.list_sessions("tenant") == []
    assert store.commit_trace_page(checkpoint(), [observation()], expected_revision=0).inserted == 1


def test_resume_cannot_change_the_original_window(store):
    store.commit_trace_page(checkpoint(), [observation()], expected_revision=0)
    changed = replace(checkpoint(2), window_start="2026-10-10T00:00:00Z")
    with pytest.raises(ValueError, match="window"):
        store.commit_trace_page(changed, [observation("wrong-window")], expected_revision=1)
    assert store.get_trace_import("tenant", "source") == checkpoint()
    assert len(store.list_observations("tenant")) == 1


def test_completed_window_cannot_be_reopened_under_the_same_import_id(store):
    completed = replace(checkpoint(), cursor=None, complete=True)
    store.commit_trace_page(completed, [], expected_revision=0)
    with pytest.raises(ValueError, match="complete"):
        store.commit_trace_page(checkpoint(2), [observation()], expected_revision=1)
    assert store.list_observations("tenant") == []
    assert store.get_trace_import("tenant", "source") == completed
