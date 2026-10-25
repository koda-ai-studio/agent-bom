"""Background graph readers finish while the test's stores still exist."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_worker_drains_before_store_fixture_and_monkeypatch_teardown(tmp_path):
    root = Path(__file__).resolve().parents[1]
    child = tmp_path / "test_owned_worker.py"
    child.write_text("""
import threading
import pytest
from tests import conftest as isolation
from agent_bom.api import graph_rollup_prewarm as warmup, stores

@pytest.fixture
def owned_store(monkeypatch):
    sentinel = object()
    release, started = threading.Event(), threading.Event()
    observed = []
    original_drain = isolation._drain_graph_warmups
    def drain():
        release.set()
        original_drain()
    def read(store, *, tenant_id):
        started.set()
        if release.wait(5):
            observed.append(store is sentinel and stores._graph_store is sentinel)
        return 0
    monkeypatch.setenv("AGENT_BOM_GRAPH_ROLLUP_PREWARM", "1")
    monkeypatch.setattr(stores, "_graph_store", sentinel)
    monkeypatch.setattr(warmup, "prewarm_rollup", read)
    monkeypatch.setattr(isolation, "_drain_graph_warmups", drain)
    yield started
    try:
        assert observed == [True], "worker outlived its store fixture"
    finally:
        release.set()
        assert warmup.wait_idle(5)

def test_queued_reader(owned_store):
    warmup.schedule_rollup_prewarm(lambda: stores._graph_store, tenant_id="fixture-tenant")
    assert owned_store.wait(5)
""")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "tests.conftest", "--confcutdir", str(tmp_path), str(child)],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(root), str(root / "src")))},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_drain_failure_still_allows_fixture_cleanup(monkeypatch):
    import pytest

    from tests import conftest as isolation

    with monkeypatch.context() as patch:
        patch.setattr(isolation, "_drain_scan_executor", lambda: None)

        def failed_drain():
            raise AssertionError("worker is still active")

        patch.setattr(isolation, "_drain_graph_warmups", failed_drain)
        hook = isolation.pytest_runtest_teardown(None, None)
        # Yield control to pytest's fixture finalizers even when draining failed.
        next(hook)
        with pytest.raises(AssertionError, match="worker is still active"):
            next(hook)
