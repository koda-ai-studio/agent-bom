"""Bounded, separately scheduled failed-authentication receipts.

An audit write can wait on a table lock, a slow disk or a stalled pool. None of
that may reach a caller who is authenticating, so receipts never use the
workers or slots that answer authentication. Their own queue is bounded, and a
receipt that cannot be queued or written is counted, logged and later recorded
in the audit chain itself, so a gap is visible rather than silent.
"""

from __future__ import annotations

import atexit
import contextvars
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from agent_bom.api import audit_log, metrics

_LOGGER = logging.getLogger(__name__)
_QUEUE_CAPACITY = 256
_PER_SOURCE_CAPACITY = 8
_WORKERS = 2
_LOG_INTERVAL_SECONDS = 60.0
_GAP_INTERVAL_SECONDS = 5.0
_GAP_SAMPLE_SOURCES = 20
_EXIT_FLUSH_SECONDS = 2.0


@dataclass(frozen=True)
class _Receipt:
    source: str
    observed_at: float
    allowed: Callable[[str, float], bool]
    details: dict[str, Any]
    context: contextvars.Context


class AuthFailureReceipts:
    def __init__(
        self,
        *,
        capacity: int = _QUEUE_CAPACITY,
        per_source: int = _PER_SOURCE_CAPACITY,
        gap_interval_seconds: float = _GAP_INTERVAL_SECONDS,
    ) -> None:
        self._queue: queue.Queue[_Receipt] = queue.Queue(maxsize=capacity)
        self._per_source = per_source
        self._lock = threading.Lock()
        self._queued_by_source: dict[str, int] = {}
        self._unrecorded_drops = 0
        self._gap_interval = gap_interval_seconds
        self._gap_sources: set[str] = set()
        self._gap_source_count = 0
        self._gap_started_at = 0.0
        self._gap_ended_at = 0.0
        self._last_gap_write = 0.0
        self._last_logged = 0.0
        self._started = False

    def submit(self, source: str, observed_at: float, allowed: Callable[[str, float], bool], **details: Any) -> None:
        """Queue one receipt without blocking; a refused receipt is counted."""
        with self._lock:
            if self._queued_by_source.get(source, 0) >= self._per_source:
                refused = "source_queue_full"
            else:
                refused = ""
                self._queued_by_source[source] = self._queued_by_source.get(source, 0) + 1
            self._start_workers()
        if refused:
            self._dropped(refused, source=source, observed_at=observed_at)
            return
        receipt = _Receipt(source, observed_at, allowed, details, contextvars.copy_context())
        try:
            self._queue.put_nowait(receipt)
        except queue.Full:
            self._release(source)
            self._dropped("queue_full", source=source, observed_at=observed_at)

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait for queued receipts; used at shutdown and by tests."""
        deadline = time.monotonic() + timeout
        with self._queue.all_tasks_done:
            while self._queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._queue.all_tasks_done.wait(remaining)
        self._write_gap(force=True)
        return True

    def _start_workers(self) -> None:
        if self._started:
            return
        self._started = True
        for number in range(_WORKERS):
            # Daemon threads: a held audit lock must not delay process exit.
            threading.Thread(target=self._work, name=f"auth-receipt-{number}", daemon=True).start()

    def _work(self) -> None:
        while True:
            try:
                receipt = self._queue.get(timeout=self._gap_interval)
            except queue.Empty:
                # Nothing else may ever arrive, so a gap must not wait for another failure.
                self._write_gap()
                continue
            try:
                receipt.context.run(self._write, receipt)
            except Exception as exc:  # broad-except: A failed evidence write is counted; it must never reach an authenticating caller.
                self._dropped("write_failed", type(exc).__name__, source=receipt.source, observed_at=receipt.observed_at)
            finally:
                self._release(receipt.source)
                self._queue.task_done()

    def _write(self, receipt: _Receipt) -> None:
        if not receipt.allowed(receipt.source, receipt.observed_at):
            self._dropped("over_budget", log=False, source=receipt.source, observed_at=receipt.observed_at)
            return
        audit_log.log_action(
            "auth.failed",
            actor="unauthenticated",
            resource="authentication",
            tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT,
            source=receipt.source,
            **receipt.details,
        )
        self._write_gap()

    def _write_gap(self, *, force: bool = False) -> None:
        """Record what was dropped, at most once per interval, keeping the counts if the write fails."""
        with self._lock:
            now = time.monotonic()
            if not self._unrecorded_drops or (not force and now - self._last_gap_write < self._gap_interval):
                return
            self._last_gap_write = now
            count, self._unrecorded_drops = self._unrecorded_drops, 0
            sources, self._gap_sources = self._gap_sources, set()
            source_count, self._gap_source_count = self._gap_source_count, 0
            started, ended = self._gap_started_at, self._gap_ended_at
            self._gap_started_at = self._gap_ended_at = 0.0
        recorded = False
        try:
            audit_log.log_action(
                "auth.receipts_dropped",
                actor="system",
                resource="authentication",
                tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT,
                dropped_receipts=count,
                dropped_source_count=source_count,
                dropped_sources=sorted(sources),
                window_started_at=_iso(started),
                window_ended_at=_iso(ended),
            )
            recorded = True
        except Exception as exc:  # broad-except: Kept for the next attempt; this runs where no caller can receive it.
            _LOGGER.error("Could not record dropped authentication receipts (%s)", type(exc).__name__)
        finally:
            if not recorded:
                with self._lock:
                    self._unrecorded_drops += count
                    self._gap_sources |= sources
                    self._gap_source_count += source_count
                    self._gap_started_at = min(self._gap_started_at or started, started)
                    self._gap_ended_at = max(self._gap_ended_at, ended)

    def _release(self, source: str) -> None:
        with self._lock:
            remaining = self._queued_by_source.get(source, 1) - 1
            if remaining > 0:
                self._queued_by_source[source] = remaining
            else:
                self._queued_by_source.pop(source, None)

    def _dropped(self, reason: str, error: str = "", *, log: bool = True, source: str = "", observed_at: float = 0.0) -> None:
        metrics.record_auth_receipt_dropped(reason)
        now = time.monotonic()
        with self._lock:
            self._unrecorded_drops += 1
            observed = observed_at or time.time()
            self._gap_started_at = min(self._gap_started_at or observed, observed)
            self._gap_ended_at = max(self._gap_ended_at, observed)
            if source and source not in self._gap_sources:
                self._gap_source_count += 1
                if len(self._gap_sources) < _GAP_SAMPLE_SOURCES:
                    self._gap_sources.add(source)
            should_log = log and now - self._last_logged >= _LOG_INTERVAL_SECONDS
            if should_log:
                self._last_logged = now
            total = self._unrecorded_drops
        if should_log:
            _LOGGER.error(
                "Failed-authentication receipts are being dropped (%s %s); %d not yet recorded. See agent_bom_auth_receipts_dropped_total.",
                reason,
                error,
                total,
            )


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


RECEIPTS = AuthFailureReceipts()


def _flush_at_exit() -> None:
    if not RECEIPTS.flush(timeout=_EXIT_FLUSH_SECONDS):
        _LOGGER.error("Exited with failed-authentication receipts still unwritten.")


atexit.register(_flush_at_exit)
