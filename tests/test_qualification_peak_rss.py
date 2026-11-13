"""The performance lane records the API's peak memory where /proc does not exist."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

QUALIFICATION = Path(__file__).resolve().parents[1] / "scripts" / "qualification"
sys.path.insert(0, str(QUALIFICATION))

import performance  # noqa: E402

_ALLOCATE = "import time\nblock = bytearray(160 * 1024 * 1024)\nblock[::4096] = b'x' * len(block[::4096])\ntime.sleep(30)\n"


def test_peak_rss_is_sampled_without_proc(monkeypatch) -> None:
    monkeypatch.setattr(performance, "_proc_peak_kib", lambda pid: None)
    child = subprocess.Popen([sys.executable, "-c", _ALLOCATE])  # noqa: S603
    tracker = performance.PeakRss(child.pid, interval=0.05)
    try:
        deadline = time.monotonic() + 15
        peak = None
        while time.monotonic() < deadline:
            peak = tracker.peak_mb()
            if peak and peak >= 150:
                break
            time.sleep(0.1)
        assert peak is not None and peak >= 150, peak
        assert tracker.source == "sampled"
    finally:
        tracker.stop()
        child.kill()
        child.wait()


def test_peak_rss_prefers_the_kernel_high_water_mark(monkeypatch) -> None:
    monkeypatch.setattr(performance, "_proc_peak_kib", lambda pid: 2048 * 1024)
    tracker = performance.PeakRss(999_999_999, interval=0.05)
    try:
        assert tracker.peak_mb() == 2048.0
        assert tracker.source == "kernel_high_water_mark"
    finally:
        tracker.stop()


def test_peak_rss_is_unknown_for_a_process_never_seen(monkeypatch) -> None:
    monkeypatch.setattr(performance, "_proc_peak_kib", lambda pid: None)
    tracker = performance.PeakRss(999_999_999, interval=0.05)
    try:
        time.sleep(0.2)
        assert tracker.peak_mb() is None
    finally:
        tracker.stop()


def test_timed_reads_report_a_warm_summary_without_the_first_read(monkeypatch) -> None:
    durations = iter([0.2] + [0.0] * 9)

    def fake_http_json(url, *, headers=None, timeout=60, **kwargs):
        time.sleep(next(durations))
        return 200, {"nodes": []}, 10

    monkeypatch.setattr(performance, "http_json", fake_http_json)

    class Server:
        base = "http://127.0.0.1:1"
        headers: dict[str, str] = {}

    timing = performance.timed_reads(Server(), "/v1/graph?limit=100", repeats=10)["timing"]  # type: ignore[arg-type]
    assert timing["cold_ms"] >= 150
    assert timing["warm"]["samples"] == 9
    assert timing["warm"]["max_ms"] < 150
    assert len(timing["samples_ms"]) == 10 and timing["samples_ms"][0] >= 150
