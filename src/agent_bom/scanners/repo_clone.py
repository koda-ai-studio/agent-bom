"""Bound a clone subprocess and its descendants while data is arriving."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable


def _stop_group(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
            )
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def run_bounded_clone(
    cmd: list[str], *, env: dict[str, str], timeout: float, check_bounds: Callable[[], None]
) -> subprocess.CompletedProcess:
    """Check disk budgets throughout the clone; retain at most 4 KiB of stderr.

    Polling bounds detection latency, not instantaneous disk consumption. A
    filesystem quota is still needed for a strict allocation ceiling.
    """
    stderr = bytearray()
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
    )

    def drain() -> None:
        assert proc.stderr is not None
        while chunk := proc.stderr.read(4096):
            remaining = 4096 - len(stderr)
            if remaining > 0:
                stderr.extend(chunk[:remaining])

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    try:
        while True:
            check_bounds()
            if proc.poll() is not None:
                check_bounds()
                break
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(cmd, timeout)
            time.sleep(0.05)
    finally:
        _stop_group(proc)
        reader.join(timeout=5)
        if proc.stderr is not None:
            proc.stderr.close()

    return subprocess.CompletedProcess(cmd, proc.returncode, stderr=stderr.decode("utf-8", errors="replace"))
