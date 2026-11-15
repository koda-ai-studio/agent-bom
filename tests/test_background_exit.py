"""Background warm-ups finish, or stop, before the interpreter finalizes.

A daemon thread still running Python when the interpreter finalizes is ended
on Python 3.11-3.13 with ``pthread_exit``; inside pydantic-core's native frames
that aborts the process (``FATAL: exception not rethrown``, SIGABRT) or crashes
it (SIGSEGV). The nightly workflow benchmark's cancel-recovery child died that
way after a push it had already stored.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from agent_bom.api import background_exit, exec_read_prewarm
from agent_bom.api.current_graph_builds import CurrentBuildQueue

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_EXEC_PREWARM", "1")
    background_exit.reset_background_exit()
    yield
    background_exit.reset_background_exit()


def test_drain_stops_new_work_and_names_what_is_still_running() -> None:
    release = threading.Event()
    background_exit.register_exit_wait("quick", lambda timeout: True)
    background_exit.register_exit_wait("stuck", lambda timeout: release.wait(timeout))
    try:
        assert background_exit.drain_background_work(0.05) == ["stuck"]
        assert background_exit.stopping()
    finally:
        release.set()
        background_exit.unregister_exit_wait("quick")
        background_exit.unregister_exit_wait("stuck")


def test_a_failing_wait_never_stops_the_drain() -> None:
    def broken(timeout: float) -> bool:
        raise RuntimeError("store gone")

    background_exit.register_exit_wait("broken", broken)
    try:
        assert background_exit.drain_background_work(0.05) == ["broken"]
    finally:
        background_exit.unregister_exit_wait("broken")


def test_no_exec_warm_up_starts_once_the_process_is_stopping() -> None:
    background_exit.drain_background_work(0.0)
    assert exec_read_prewarm.schedule_exec_prewarm("tenant-a") is False
    assert exec_read_prewarm.pending_exec_prewarms() == set()


def test_a_build_queued_after_the_executor_shut_down_is_skipped_not_raised() -> None:
    queue = CurrentBuildQueue(workers=1)
    queue.executor.shutdown(wait=True)

    class Store:
        pass

    assert queue.submit(Store(), "tenant-a", after_commit=True) is None


_CHILD = textwrap.dedent(
    """
    import asyncio, sys, time
    from pathlib import Path

    from pydantic import BaseModel, field_validator

    from agent_bom.api import exec_read_prewarm as prewarm

    marker = Path(sys.argv[1])

    class Row(BaseModel):
        values: list[int]

        @field_validator("values")
        @classmethod
        def _python_validator(cls, value):
            sum(range(500))
            return value

    async def slow_read(request, **params):
        # Native validation frames around Python callbacks, like a real read model.
        until = time.monotonic() + 1.5
        while time.monotonic() < until:
            Row.model_validate({"values": list(range(64))})
        marker.write_text("first read finished", encoding="utf-8")

    async def second_read(request, **params):
        Path(str(marker) + ".second").write_text("ran", encoding="utf-8")

    prewarm.EXEC_READS = ((slow_read, "/slow", {}), (second_read, "/second", {}))
    assert prewarm.schedule_exec_prewarm("tenant-a")
    time.sleep(0.2)
    """
)


def test_process_exit_lets_a_running_warm_up_finish_its_read_and_skips_the_rest(tmp_path: Path) -> None:
    marker = tmp_path / "warm.done"
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "AGENT_BOM_STATE_DIR": str(tmp_path / "state"),
            "AGENT_BOM_DB": str(tmp_path / "control-plane.db"),
            "AGENT_BOM_EXEC_PREWARM": "1",
            "PYTHONPATH": str(ROOT / "src"),
        }
    )
    completed = subprocess.run(
        [sys.executable, "-c", _CHILD, str(marker)], env=env, capture_output=True, text=True, timeout=60, check=False
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "exception not rethrown" not in completed.stderr
    assert marker.read_text(encoding="utf-8") == "first read finished"
    assert not Path(str(marker) + ".second").exists()
