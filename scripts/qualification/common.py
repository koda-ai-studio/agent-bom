"""Shared helpers for the cloud qualification lanes.

Every lane records named checks, measurements and product defects in one JSON
document under ``qualification-results/``. A lane fails when a check fails or a
defect is recorded; a lane never turns a product failure into a pass.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = REPO_ROOT / "qualification-results"


class LaneResult:
    """Collects the outcome of one lane variant and writes it as JSON."""

    def __init__(self, lane: str, variant: str = "default") -> None:
        self.lane = lane
        self.variant = variant
        self.checks: list[dict[str, Any]] = []
        self.measurements: dict[str, Any] = {}
        self.defects: list[dict[str, str]] = []
        self.not_tested: list[dict[str, str]] = []
        self.started = time.monotonic()

    def check(self, name: str, ok: bool, detail: Any = "") -> bool:
        self.checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:2000]})
        print(f"{'PASS' if ok else 'FAIL'} {name}: {str(detail)[:400]}", flush=True)
        return bool(ok)

    def defect(self, defect_id: str, summary: str, reproduction: str) -> None:
        self.defects.append({"id": defect_id, "summary": summary, "reproduction": reproduction})
        print(f"DEFECT {defect_id}: {summary}", flush=True)

    def skip(self, area: str, reason: str) -> None:
        self.not_tested.append({"area": area, "reason": reason})
        print(f"NOT TESTED {area}: {reason}", flush=True)

    @property
    def passed(self) -> bool:
        return all(item["ok"] for item in self.checks) and not self.defects and bool(self.checks)

    def document(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "lane": self.lane,
            "variant": self.variant,
            "status": "passed" if self.passed else "failed",
            "duration_seconds": round(time.monotonic() - self.started, 1),
            "checks": self.checks,
            "measurements": self.measurements,
            "defects": self.defects,
            "not_tested": self.not_tested,
            "environment": {
                "os": platform.system(),
                "os_release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "cpu_count": os.cpu_count(),
                "runner": os.environ.get("RUNNER_NAME", ""),
                "image": os.environ.get("ImageOS", ""),
                "image_version": os.environ.get("ImageVersion", ""),
                "git_sha": os.environ.get("GITHUB_SHA", ""),
                "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            },
        }

    def write(self, directory: Path = RESULTS_DIR) -> int:
        """Write the result file and return the process exit code."""
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.lane}-{self.variant}.json"
        path.write_text(json.dumps(self.document(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{self.lane}/{self.variant}: {'passed' if self.passed else 'FAILED'} -> {path}", flush=True)
        return 0 if self.passed else 1


@dataclass
class RunResult:
    returncode: int
    seconds: float
    peak_rss_mb: float | None
    stdout: str
    stderr: str
    timed_out: bool = False


def _rss_to_mb(ru_maxrss: int) -> float:
    # getrusage reports kilobytes on Linux and bytes on macOS.
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    return round(ru_maxrss / divisor, 1)


def run_measured(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | str | None = None,
    timeout: float = 1800,
    log_dir: Path | None = None,
) -> RunResult:
    """Run a command, returning exit code, wall time and peak memory where the OS reports it."""
    log_dir = log_dir or (RESULTS_DIR / "logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{int(time.time() * 1000)}-{Path(command[0]).stem}"
    out_path, err_path = log_dir / f"{stem}.out", log_dir / f"{stem}.err"
    print("+ " + " ".join(command), flush=True)
    started = time.monotonic()
    peak: float | None = None
    timed_out = False
    with out_path.open("wb") as out, err_path.open("wb") as err:
        process = subprocess.Popen(command, env=env, cwd=cwd, stdout=out, stderr=err, stdin=subprocess.DEVNULL)  # noqa: S603
        if hasattr(os, "wait4"):
            returncode = None
            while returncode is None:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    returncode = os.waitstatus_to_exitcode(status)
                    peak = _rss_to_mb(usage.ru_maxrss)
                    process.returncode = returncode
                elif time.monotonic() - started > timeout:
                    timed_out = True
                    process.kill()
                    time.sleep(1)
                else:
                    time.sleep(0.05)
        else:
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                returncode = process.wait()
    return RunResult(
        returncode=returncode,
        seconds=round(time.monotonic() - started, 2),
        peak_rss_mb=peak,
        stdout=out_path.read_text(encoding="utf-8", errors="replace"),
        stderr=err_path.read_text(encoding="utf-8", errors="replace"),
        timed_out=timed_out,
    )


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile; an empty sample is reported as 0.0 with samples=0 by the caller."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * pct / 100)))
    return round(ordered[index], 3)


def latency_summary(values_ms: list[float]) -> dict[str, float | int]:
    return {
        "samples": len(values_ms),
        "p50_ms": percentile(values_ms, 50),
        "p95_ms": percentile(values_ms, 95),
        "max_ms": round(max(values_ms), 3) if values_ms else 0.0,
        "mean_ms": round(statistics.fmean(values_ms), 3) if values_ms else 0.0,
    }


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_json(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 60,
) -> tuple[int, Any, int]:
    """Return ``(status, parsed body or raw text, response bytes)``; status 0 means no response."""
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, {"error": str(exc)}, 0
    try:
        return status, json.loads(raw) if raw else {}, len(raw)
    except ValueError:
        return status, raw.decode("utf-8", errors="replace"), len(raw)


def wait_for_http(url: str, *, timeout: float = 120, headers: dict[str, str] | None = None) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, _body, _size = http_json(url, headers=headers, timeout=5)
        if status == 200:
            return True
        time.sleep(1)
    return False


def agent_bom_command(*args: str) -> list[str]:
    """Invoke the console script beside this interpreter, as an installed user would."""
    script = Path(sys.executable).parent / ("agent-bom.exe" if sys.platform == "win32" else "agent-bom")
    return [str(script), *args] if script.exists() else [sys.executable, "-m", "agent_bom", *args]


def tail(text: str, lines: int = 25) -> str:
    return "\n".join(text.splitlines()[-lines:])
