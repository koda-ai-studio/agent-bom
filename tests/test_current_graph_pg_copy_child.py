"""The PostgreSQL row copy runs in a bounded child process that never sees its credentials in argv.

A row copy in the API process held the interpreter lock for its whole run
beside every graph read after a large push. In a child it holds none of the
API's. The child is bounded: a timeout kills it, any non-zero exit is a clean
fallback to the in-process rebuild, and shutdown leaves no child behind. Its
errors are logged sanitized, without connection strings.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from agent_bom.api import current_graph_pg_copy_child as child

SECRET = "child-test-password-7f3a"
URL = f"postgresql://agent_bom_app:{SECRET}@db.internal:5432/agent_bom"
FIELDS = {
    "tenant": "tenant-a",
    "source_scan": "scan-1",
    "expected_revision": "rev-1",
    "identity": "current-estate:abc",
    "created_at": "2026-11-14T00:00:00Z",
    "write_generation": "abc",
    "evidence_manifest_sha256": "sha256:abc",
}


def _module(tmp_path: Path, monkeypatch, name: str, body: str) -> str:
    package = tmp_path / "copy_children"
    package.mkdir(exist_ok=True)
    (package / "__init__.py").write_text("")
    (package / f"{name}.py").write_text(body)
    paths = [str(tmp_path), *(os.environ.get("PYTHONPATH", "").split(os.pathsep))]
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(path for path in paths if path))
    return f"copy_children.{name}"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _spawned(monkeypatch) -> list[subprocess.Popen]:
    started: list[subprocess.Popen] = []
    real = subprocess.Popen

    def recording(*args, **kwargs):
        process = real(*args, **kwargs)
        started.append(process)
        return process

    monkeypatch.setattr(child.subprocess, "Popen", recording)
    return started


def test_the_connection_string_never_reaches_argv_or_the_request(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", URL)
    seen: dict[str, object] = {}

    class FakeProcess:
        returncode = child.EXIT_COPIED
        pid = 1

        def __init__(self, args, **kwargs):
            seen["argv"] = list(args)
            seen["env"] = kwargs["env"]

        def communicate(self, payload=None, timeout=None):
            seen["payload"] = payload
            return b"", b""

    monkeypatch.setattr(child.subprocess, "Popen", FakeProcess)
    assert child.copy_in_child(str(tmp_path / "projection.db"), **FIELDS) is True
    assert SECRET not in " ".join(seen["argv"]) and "postgresql://" not in " ".join(seen["argv"])
    assert SECRET not in seen["payload"].decode()
    # The child reads the connection from the environment it inherits, as the API does.
    assert seen["env"]["AGENT_BOM_POSTGRES_URL"] == URL


def test_a_child_that_overruns_its_timeout_is_killed_and_the_build_falls_back(tmp_path, monkeypatch, caplog) -> None:
    module = _module(tmp_path, monkeypatch, "sleeper", "import time\ntime.sleep(120)\n")
    started = _spawned(monkeypatch)
    began = time.monotonic()
    with caplog.at_level(logging.WARNING):
        assert child.copy_in_child(str(tmp_path / "projection.db"), module=module, timeout=1.0, **FIELDS) is False
    assert time.monotonic() - began < 30
    assert len(started) == 1 and started[0].poll() is not None
    assert not _alive(started[0].pid)
    assert "timed out" in caplog.text
    assert not child.live_children()


def test_a_failing_child_falls_back_and_its_error_is_logged_without_secrets(tmp_path, monkeypatch, caplog) -> None:
    body = f"import sys\nsys.stderr.write('connect failed: {URL}\\n')\nsys.exit(3)\n"
    module = _module(tmp_path, monkeypatch, "failer", body)
    with caplog.at_level(logging.WARNING):
        assert child.copy_in_child(str(tmp_path / "projection.db"), module=module, timeout=30, **FIELDS) is False
    assert "exit 3" in caplog.text
    assert SECRET not in caplog.text


def test_a_declining_child_falls_back_quietly(tmp_path, monkeypatch, caplog) -> None:
    module = _module(tmp_path, monkeypatch, "decliner", f"import sys\nsys.exit({child.EXIT_DECLINED})\n")
    with caplog.at_level(logging.WARNING):
        assert child.copy_in_child(str(tmp_path / "projection.db"), module=module, timeout=30, **FIELDS) is False
    assert "row copy" not in caplog.text


def test_shutdown_kills_a_running_child(tmp_path, monkeypatch) -> None:
    module = _module(tmp_path, monkeypatch, "sleeper", "import time\ntime.sleep(120)\n")
    started = _spawned(monkeypatch)
    results: list[bool] = []
    worker = threading.Thread(
        target=lambda: results.append(child.copy_in_child(str(tmp_path / "projection.db"), module=module, timeout=120, **FIELDS))
    )
    worker.start()
    deadline = time.monotonic() + 20
    while not child.live_children() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert child.live_children()
    child.terminate_children()
    worker.join(20)
    assert results == [False]
    assert not _alive(started[0].pid)
    assert not child.live_children()


def test_the_child_exits_when_its_parent_is_gone(monkeypatch) -> None:
    from agent_bom.api import current_graph_pg_copy_worker as worker

    exits: list[int] = []
    monkeypatch.setattr(worker.os, "getppid", lambda: 1)
    monkeypatch.setattr(worker.os, "_exit", exits.append)
    worker.exit_if_orphaned(parent_pid=4242)
    assert exits == [child.EXIT_FAILED]
    exits.clear()
    worker.exit_if_orphaned(parent_pid=1)
    assert exits == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process semantics")
def test_the_child_entry_point_reports_bad_requests_without_echoing_them(tmp_path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed interpreter and module
        [sys.executable, "-m", child.CHILD_MODULE],
        input=f'{{"not": "{URL}"}}'.encode(),
        capture_output=True,
        timeout=60,
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join([str(Path(child.__file__).resolve().parents[2]), os.environ.get("PYTHONPATH", "")]),
        },
    )
    assert result.returncode == child.EXIT_FAILED
    assert SECRET not in result.stderr.decode()


def test_the_child_lowers_its_cpu_priority_below_the_api(monkeypatch) -> None:
    """The copy child and PostgreSQL serving it shared four cores with the API after a large push."""
    from agent_bom.api import current_graph_pg_copy_worker as worker

    calls: list[int] = []
    monkeypatch.setattr(worker.os, "nice", calls.append, raising=False)
    worker.lower_priority()
    assert calls == [worker.NICE_INCREMENT] and worker.NICE_INCREMENT > 0


def test_lowering_priority_never_fails_the_copy(monkeypatch) -> None:
    from agent_bom.api import current_graph_pg_copy_worker as worker

    monkeypatch.delattr(worker.os, "nice", raising=False)
    worker.lower_priority()

    def refused(_increment: int) -> int:
        raise PermissionError("not permitted")

    monkeypatch.setattr(worker.os, "nice", refused, raising=False)
    worker.lower_priority()


def test_the_child_lowers_its_priority_before_it_reads_its_request(monkeypatch) -> None:
    from agent_bom.api import current_graph_pg_copy_worker as worker

    order: list[str] = []

    class Stdin:
        class buffer:  # noqa: N801 - mirrors sys.stdin.buffer
            @staticmethod
            def read() -> bytes:
                order.append("read")
                raise RuntimeError("stop before any database work")

    monkeypatch.setattr(worker, "lower_priority", lambda: order.append("nice"))
    monkeypatch.setattr(worker.sys, "stdin", Stdin)
    monkeypatch.setattr(worker.sys, "excepthook", worker.sys.excepthook)
    with pytest.raises(RuntimeError):
        worker.main()
    assert order == ["nice", "read"]
