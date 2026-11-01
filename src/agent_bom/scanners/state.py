"""Shared scanner runtime state helpers."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from agent_bom.config import SCANNER_MAX_CONCURRENT as MAX_CONCURRENT_REQUESTS
from agent_bom.core.errors import DegradedCoverage

_coverage_capture: ContextVar[list[dict] | None] = ContextVar("coverage_capture", default=None)


@contextmanager
def capture_coverage_warnings() -> Iterator[list[dict]]:
    recorded: list[dict] = []
    token = _coverage_capture.set(recorded)
    try:
        yield recorded
    finally:
        _coverage_capture.reset(token)


_logger = logging.getLogger(__name__)

_scan_state_local = threading.local()
_SCAN_PERF_TEMPLATE = {
    "unfixed_os_findings_suppressed": 0,
    "packages_seen": 0,
    "packages_deduplicated": 0,
    "osv_cache_hits": 0,
    "osv_cache_hits_with_vulns": 0,
    "osv_cache_hits_clean": 0,
    "osv_cache_misses": 0,
    "osv_packages_queried": 0,
    "osv_queries_sent": 0,
    "osv_batches": 0,
    # Batches OSV actually answered; together with cache hits this is the
    # evidence that live OSV backed a lookup, not merely that one was planned.
    "osv_batches_answered": 0,
    "osv_lookup_errors": 0,
    "offline_skips": 0,
    "skipped_unresolvable_versions": 0,
    "skipped_non_osv_ecosystems": 0,
}
_loop_semaphores_lock = threading.Lock()
_MAX_CACHED_LOOPS = 8
_loop_semaphores: dict[int, asyncio.Semaphore] = {}


def _scan_warnings_state() -> list[str]:
    warnings = getattr(_scan_state_local, "warnings", None)
    if warnings is None:
        warnings = []
        _scan_state_local.warnings = warnings
    return warnings


def _coverage_warnings_state() -> list[dict]:
    warnings = getattr(_scan_state_local, "coverage_warnings", None)
    if warnings is None:
        warnings = []
        _scan_state_local.coverage_warnings = warnings
    return warnings


def _scan_performance_state() -> dict[str, int]:
    perf = getattr(_scan_state_local, "performance", None)
    if perf is None:
        perf = dict(_SCAN_PERF_TEMPLATE)
        _scan_state_local.performance = perf
    return perf


def reset_scan_warnings() -> None:
    """Reset all scan warning channels at a command/request boundary."""
    _scan_state_local.warnings = []
    _scan_state_local.coverage_warnings = []
    _scan_state_local.resolution_deadline = None
    _scan_state_local.epss_outcome = None
    _scan_state_local.epss_summary = None


def scan_scoped_deadline(seconds: float, now: float) -> float:
    """One deadline per scan, created on first use and cleared by :func:`reset_scan_warnings`."""
    deadline = getattr(_scan_state_local, "resolution_deadline", None)
    if deadline is None:
        deadline = now + seconds
        _scan_state_local.resolution_deadline = deadline
    return deadline


def reset_scan_warnings_only() -> None:
    """Reset transient scanner warnings without discarding parser coverage gaps.

    Project manifest parsers can run before vulnerability scanning and record a
    structured coverage warning. The package scanner must clear warnings from a
    prior scan, but must preserve those parser warnings for the final report.
    """
    _scan_state_local.warnings = []


def record_scan_warning(message: str) -> None:
    warnings = _scan_warnings_state()
    if message not in warnings:
        warnings.append(message)


def record_degraded_coverage(degraded: DegradedCoverage | None) -> None:
    """Surface a partial upstream answer on the scan's warning channel."""
    if degraded is None:
        return
    _logger.warning("%s", degraded.message())
    record_scan_warning(degraded.message())


def peek_scan_warnings() -> list[str]:
    """Read lookup warnings without consuming the final report's evidence."""
    return list(_scan_warnings_state())


def consume_scan_warnings() -> list[str]:
    warnings_state = _scan_warnings_state()
    warnings = list(warnings_state)
    _scan_state_local.warnings = []
    return warnings


def restore_scan_warnings(warnings: list[str], coverage_warnings: list[dict]) -> None:
    """Re-record warnings a worker thread drained from its own thread-local channels.

    Bypasses the coverage capture: a capture active in the worker already saw them.
    """
    for message in warnings:
        record_scan_warning(message)
    channel = _coverage_warnings_state()
    for warning in coverage_warnings:
        if not any(existing.get("release") == warning.get("release") for existing in channel):
            channel.append(warning)


def record_coverage_warning(warning: dict, *, replace: bool = False) -> None:
    """Record a structured per-release coverage-gap warning (deduped by release).

    ``replace`` swaps an earlier entry for the same release instead of keeping
    it, for receipts whose detail accumulates across scanner batches.
    """
    captured = _coverage_capture.get()
    if captured is not None:
        captured.append(dict(warning))
    warnings = _coverage_warnings_state()
    release = warning.get("release")
    if any(existing.get("release") == release for existing in warnings):
        if not replace:
            return
        warnings[:] = [existing for existing in warnings if existing.get("release") != release]
    warnings.append(warning)


def peek_coverage_warnings() -> list[dict]:
    """Read the structured coverage warnings without draining them.

    The scanner needs to see what a sub-step recorded (e.g. an OSV lookup
    failure) while leaving the channel intact for the command boundary that
    actually consumes it.
    """
    return list(_coverage_warnings_state())


def consume_coverage_warnings() -> list[dict]:
    warnings_state = _coverage_warnings_state()
    warnings = list(warnings_state)
    _scan_state_local.coverage_warnings = []
    return warnings


def reset_scan_performance() -> None:
    _scan_state_local.performance = dict(_SCAN_PERF_TEMPLATE)


def _bump_scan_perf(key: str, delta: int = 1) -> None:
    performance = _scan_performance_state()
    performance[key] = int(performance.get(key, 0)) + delta


def peek_scan_performance() -> dict[str, int]:
    """Read this scan's performance counters without resetting them."""
    return dict(_scan_performance_state())


def consume_scan_performance() -> dict[str, int]:
    snapshot = dict(_scan_performance_state())
    reset_scan_performance()
    total_cache = snapshot["osv_cache_hits"] + snapshot["osv_cache_misses"]
    if total_cache:
        snapshot["osv_cache_hit_rate_pct"] = int(round((snapshot["osv_cache_hits"] / total_cache) * 100))
    return snapshot


def _get_api_semaphore() -> asyncio.Semaphore:
    """Get or create a semaphore bound to the current running event loop."""
    loop = asyncio.get_running_loop()
    loop_id = id(loop)
    with _loop_semaphores_lock:
        if loop_id not in _loop_semaphores:
            if len(_loop_semaphores) >= _MAX_CACHED_LOOPS:
                oldest = next(iter(_loop_semaphores))
                del _loop_semaphores[oldest]
            _loop_semaphores[loop_id] = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        return _loop_semaphores[loop_id]
