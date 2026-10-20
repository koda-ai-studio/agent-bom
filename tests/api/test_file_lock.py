"""Advisory file locks degrade to in-process locking only where the filesystem cannot lock."""

from __future__ import annotations

import errno
import threading

import pytest

from agent_bom.api import file_lock
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import InMemoryJobStore


def _refuse(code: int):
    def lock(fd: int) -> None:
        raise OSError(code, "refused")

    return lock


def test_unsupported_filesystem_yields_unlocked_instead_of_failing(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(file_lock, "lock_file_descriptor", _refuse(errno.ENOLCK))
    with file_lock.exclusive_file_lock(tmp_path / "x.lock") as held:
        assert held is False
    assert "in-process locking only" in caplog.text


def test_other_lock_errors_propagate(tmp_path, monkeypatch):
    monkeypatch.setattr(file_lock, "lock_file_descriptor", _refuse(errno.EIO))
    with pytest.raises(OSError):
        with file_lock.exclusive_file_lock(tmp_path / "x.lock"):
            pass


def test_held_lock_is_reported(tmp_path):
    with file_lock.exclusive_file_lock(tmp_path / "x.lock") as held:
        assert held is True


def test_nested_promotion_lock_on_one_thread_does_not_self_deadlock(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    store = CurrentGraphStore(SQLiteGraphStore(str(tmp_path / "graph.db")), InMemoryJobStore())
    done = threading.Event()

    def nested() -> None:
        with store._promotion_lock("t"), store._promotion_lock("t"):
            done.set()

    worker = threading.Thread(target=nested, daemon=True)
    worker.start()
    assert done.wait(5), "a nested promotion lock blocked on its own file lock"
    worker.join(5)
