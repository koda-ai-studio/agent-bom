"""CPU-heavy page work must let another request run without partial commits."""

import inspect
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _probe(phase, database):
    import sys
    import threading
    import time
    from dataclasses import replace
    from types import SimpleNamespace
    from unittest.mock import patch

    from agent_bom.api import native_trace_import
    from agent_bom.api.runtime_event_store import RuntimeObservationRecord, SQLiteRuntimeEventStore
    from agent_bom.api.storage import cooperative
    from agent_bom.api.storage.sql import SQLiteBackend
    from agent_bom.api.trace_collection import langfuse
    from agent_bom.api.trace_collection.store import TraceCollectionStore
    from tests.test_trace_collection_provider import collect, row
    from tests.test_trace_collection_store import initial, observation

    runtime = SQLiteRuntimeEventStore(database)
    store = TraceCollectionStore(SQLiteBackend(database))
    store.init_schema()
    claim = store.claim("a", "connection", initial(), now=100)
    handed_off = threading.Event()
    reader_done = threading.Event()
    ready = threading.Event()
    progress = []
    count = 0

    def reader():
        assert runtime.list_observations("a") == []
        ready.set()
        assert handed_off.wait(5)
        progress.append(count)
        if phase == "serialize":
            # A scheduler handoff is not a transaction boundary.
            progress.append(len(runtime.list_observations("a")))
        reader_done.set()

    def handoff(_seconds):
        # The collector's handoff is a scheduling opportunity, not a latency
        # guarantee, so a loaded host may not run the reader inside it. Hold
        # the first handoff until the reader has looked: this asserts the
        # collector offers a handoff mid-batch without depending on the OS.
        # Earlier pipeline stages hand off too; engage once the measured step
        # has started, so the reader must see partial progress.
        if count and not handed_off.is_set():
            handed_off.set()
            assert reader_done.wait(5)

    target, name = {
        "normalize": (langfuse, "native_span"),
        "prepare": (native_trace_import, "_with_normalized"),
        "serialize": (RuntimeObservationRecord, "to_dict"),
    }[phase]
    original = getattr(target, name)

    def costly_record(*args, **kwargs):
        nonlocal count
        count += 1
        until = time.perf_counter() + 0.001
        while time.perf_counter() < until:
            pass
        return original(*args, **kwargs)

    # Isolated child only: suppress incidental interpreter handoffs so this
    # tests the collector's fairness rather than the host's default timeslice.
    sys.setswitchinterval(1.0)
    thread = threading.Thread(target=reader)
    thread.start()
    assert ready.wait(5)
    with (
        patch.object(target, name, costly_record),
        patch.object(cooperative, "time", SimpleNamespace(sleep=handoff)),
        patch("agent_bom.trace_connectors._validate_pull_url"),
    ):
        if phase == "serialize":
            records = [
                replace(
                    observation(key=f"span-{i}"),
                    surface="imported_trace",
                    metadata={"connection_id": "connection", "project_id": "project"},
                )
                for i in range(100)
            ]
            done = store.commit("a", "connection", claim, records, next_cursor=None, now=101)
            assert done.persisted == 100
        else:
            records, cursor = collect({"data": [{**row(), "id": f"span-{i}"} for i in range(100)], "meta": {}})
            assert cursor is None and len({record.observation_id for record in records}) == 100
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert progress and 0 < progress[0] < 100, progress
    if phase == "serialize":
        assert progress[1] == 0, "another request must not see a partial page"
        assert len(runtime.list_observations("a")) == 100
        assert runtime.get_session("a", "session-1").observation_count == 100


@pytest.mark.parametrize("phase", ["normalize", "prepare", "serialize"])
def test_page_work_yields_to_another_request_before_batch_completion(tmp_path, phase):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-c", inspect.getsource(_probe) + "\nimport sys\n_probe(*sys.argv[1:])", phase, str(tmp_path / "runtime.db")],
        cwd=root,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(root / "src"), str(root)))},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr[-4000:]
