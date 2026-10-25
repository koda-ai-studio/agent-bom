"""NVD 2.0 ``lastModified`` window paging under the public rate limits.

NVD documents 5 requests per rolling 30 seconds without an API key and 50 with
one (https://nvd.nist.gov/developers/start-here). The key travels only in the
``apiKey`` request header to ``services.nvd.nist.gov``; it is never put in a
URL, a log line or the database.
"""

from __future__ import annotations

import sqlite3
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import httpx

from agent_bom import http_client
from agent_bom.db.sync_common import (
    _NVD_API_URL,
    _logger,
    _nvd_api_timestamp,
    _read_sync_metadata,
    _update_sync_meta,
    _upsert_cpe_matches,
    _upsert_nvd_enrichment_row,
    _validate_sync_url,
)
from agent_bom.db.sync_parsing import _extract_nvd_cpe_matches, _extract_nvd_cve_fields

NVD_WINDOW_SECONDS = 30.0
NVD_ANONYMOUS_REQUESTS_PER_WINDOW = 5
NVD_KEYED_REQUESTS_PER_WINDOW = 50
# NVD caps a lastModified range at 120 days; keyless runs stay short enough to
# finish in a few pages at 5 requests per 30 seconds.
KEYED_LOOKBACK_DAYS = 120
KEYLESS_LOOKBACK_DAYS = 14


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


class NvdRateLimiter:
    """Rolling-window request budget; ``acquire`` blocks until a slot is free."""

    def __init__(
        self,
        max_requests: int,
        window_seconds: float = NVD_WINDOW_SECONDS,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = _sleep,
    ) -> None:
        self.max_requests = max(1, max_requests)
        self.window_seconds = window_seconds
        self._clock = clock
        self._sleep = sleep
        self._stamps: deque[float] = deque()
        self._not_before = 0.0

    @classmethod
    def for_key(cls, api_key: str | None) -> NvdRateLimiter:
        return cls(NVD_KEYED_REQUESTS_PER_WINDOW if api_key else NVD_ANONYMOUS_REQUESTS_PER_WINDOW)

    def defer(self, seconds: float) -> None:
        """Push the next request out by ``seconds`` (a server ``Retry-After``)."""
        self._not_before = max(self._not_before, self._clock() + max(0.0, seconds))

    def acquire(self) -> None:
        now = self._clock()
        wait = max(0.0, self._not_before - now)
        self._expire(now + wait)
        if len(self._stamps) >= self.max_requests:
            wait = max(wait, self._stamps[0] + self.window_seconds - now)
        if wait > 0:
            self._sleep(wait)
        # Account with the logical post-wait time so a patched or coarse
        # clock can never let a request through early or spin.
        stamp = max(self._clock(), now + wait)
        self._expire(stamp)
        self._stamps.append(stamp)

    def _expire(self, now: float) -> None:
        while self._stamps and self._stamps[0] <= now - self.window_seconds:
            self._stamps.popleft()


class NvdWindowError(Exception):
    """One window page could not be fetched; ``reason`` is recorded as the partial cause."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_RATE_LIMIT_STATUSES = frozenset({403, 429})
_RATE_LIMIT_RETRIES = 2
_FETCH_FAILURES: tuple[type[BaseException], ...] = (httpx.HTTPError, ConnectionError, OSError, ValueError, RuntimeError)


def _retry_after_seconds(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    try:
        return float(raw) if raw else None
    except ValueError:
        return None


def fetch_nvd_page(url: str, headers: dict[str, str], limiter: NvdRateLimiter) -> dict[str, Any]:
    """Fetch one NVD page inside the rate budget; 403/429 back off (``Retry-After`` first) then give up."""
    for attempt in range(_RATE_LIMIT_RETRIES + 1):
        limiter.acquire()
        try:
            data = http_client.fetch_json(url, timeout=60, headers=headers)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in _RATE_LIMIT_STATUSES:
                raise NvdWindowError("http_error") from None
            if attempt == _RATE_LIMIT_RETRIES:
                raise NvdWindowError("rate_limited") from None
            limiter.defer(_retry_after_seconds(exc.response) or limiter.window_seconds)
            continue
        except httpx.TimeoutException:
            raise NvdWindowError("timeout") from None
        except _FETCH_FAILURES:
            raise NvdWindowError("unavailable") from None
        if not isinstance(data, dict):
            raise NvdWindowError("unexpected_payload")
        return data
    raise NvdWindowError("rate_limited")


@dataclass
class _Window:
    start_ts: str
    end_ts: str
    lookback_days: int
    enriched: int = 0
    start_index: int = 0
    total_seen: int = 0
    partial_reason: str | None = None


def _window_start(conn: sqlite3.Connection, now: datetime, lookback_days: int) -> datetime:
    floor = now - timedelta(days=lookback_days)
    checkpoint = _read_sync_metadata(conn, "nvd").get("last_modified_end")
    if not (isinstance(checkpoint, str) and checkpoint.strip()):
        return floor
    try:
        start = datetime.fromisoformat(checkpoint.replace("Z", "+00:00"))
    except ValueError:
        return floor
    start = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
    return max(start, floor)


def _upsert_nvd_cve(conn: sqlite3.Connection, cve_data: dict[str, Any]) -> bool:
    """Store one NVD CVE (row, dates, CPE ranges); ``True`` when the CVE row is new."""
    cve_id = str(cve_data.get("id") or "")
    cpe_rows = _extract_nvd_cpe_matches(cve_data)
    _upsert_cpe_matches(conn, cve_id, cpe_rows)
    fields = _extract_nvd_cve_fields(cve_data)
    inserted = _upsert_nvd_enrichment_row(conn, cve_id, fields)
    if not inserted and cpe_rows:
        # A CVE NVD has analysed for applicability but not yet scored still has
        # to be matchable, so seed the row; severity stays unknown until scored.
        cur = conn.execute(
            "INSERT OR IGNORE INTO vulns (id, summary, severity, source, published, modified, cwe_ids, aliases) "
            "VALUES (?, ?, 'unknown', 'nvd', '', '', '', '')",
            (cve_id, fields.get("summary") or f"NVD entry for {cve_id}"),
        )
        inserted = cur.rowcount == 1
    conn.execute(
        "UPDATE vulns SET published = CASE WHEN published IS NULL OR published = '' THEN ? ELSE published END, "
        "modified = ? WHERE id = ? AND source = 'nvd'",
        (str(cve_data.get("published") or ""), str(cve_data.get("lastModified") or ""), cve_id),
    )
    return inserted


def _ingest_page(conn: sqlite3.Connection, items: list[Any], window: _Window, max_results: int) -> None:
    for item in items:
        cve_data = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve_data, dict) or not str(cve_data.get("id") or "").startswith("CVE-"):
            continue
        if _upsert_nvd_cve(conn, cve_data):
            window.enriched += 1
            if window.enriched >= max_results:
                break
    conn.commit()


def _page_window(
    conn: sqlite3.Connection, base_url: str, api_key: str | None, window: _Window, limiter: NvdRateLimiter, max_results: int
) -> None:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    page_size = min(2000, max_results)
    while window.enriched < max_results:
        params = {
            "lastModStartDate": window.start_ts,
            "lastModEndDate": window.end_ts,
            "resultsPerPage": page_size,
            "startIndex": window.start_index,
        }
        try:
            data = fetch_nvd_page(f"{base_url}?{urllib.parse.urlencode(params)}", headers, limiter)
        except NvdWindowError as exc:
            _logger.warning("NVD window sync stopped at startIndex=%s: %s", window.start_index, exc.reason)
            window.partial_reason = exc.reason
            return
        items = data.get("vulnerabilities") or []
        if not items:
            return
        _ingest_page(conn, items, window, max_results)
        window.total_seen = max(window.total_seen, int(data.get("totalResults") or 0))
        window.start_index += len(items)
        if window.start_index >= window.total_seen:
            return
    if window.start_index < window.total_seen:
        window.partial_reason = "truncated"
        _logger.warning(
            "NVD window sync truncated at max_results=%d (window has >=%d modified CVEs); the next run resumes the tail.",
            max_results,
            window.total_seen,
        )


def _record_window(conn: sqlite3.Connection, window: _Window, max_results: int, api_key_used: bool) -> None:
    partial = window.partial_reason is not None
    _update_sync_meta(
        conn,
        "nvd",
        window.enriched,
        {
            "mode": "incremental",
            "status": "partial" if partial else "synced",
            "partial_reason": window.partial_reason,
            "lookback_days": window.lookback_days,
            "last_modified_start": window.start_ts,
            # Advance the synced-through cursor only when the whole window was
            # fetched, so the next run retries what this one could not reach.
            "last_modified_end": window.start_ts if partial else window.end_ts,
            "max_results": max_results,
            "api_key_used": api_key_used,
            "sync_failed": partial and window.partial_reason != "truncated",
            "sync_truncated": window.partial_reason == "truncated",
        },
    )


def sync_nvd_incremental(
    conn: sqlite3.Connection,
    nvd_api_key: Optional[str] = None,
    url: Optional[str] = None,
    max_results: int = 2000,
    lookback_days: Optional[int] = None,
    limiter: Optional[NvdRateLimiter] = None,
) -> int:
    """Ingest CVEs NVD published or modified in a bounded window, CPE ranges included.

    Works with or without an API key: the key only raises the request budget
    and the default lookback (120 days keyed, 14 keyless). A rate-limited,
    timed-out or truncated window is recorded ``status: partial`` and keeps
    the checkpoint, never reported as synced.
    """
    base_url = url or _NVD_API_URL
    _validate_sync_url(base_url, "nvd url")
    days = lookback_days or (KEYED_LOOKBACK_DAYS if nvd_api_key else KEYLESS_LOOKBACK_DAYS)
    now = datetime.now(timezone.utc)
    window = _Window(_nvd_api_timestamp(_window_start(conn, now, days)), _nvd_api_timestamp(now), days)
    _page_window(conn, base_url, nvd_api_key, window, limiter or NvdRateLimiter.for_key(nvd_api_key), max_results)
    conn.commit()
    _record_window(conn, window, max_results, bool(nvd_api_key))
    _logger.info("NVD window sync %s: %d new CVE rows", "partial" if window.partial_reason else "complete", window.enriched)
    return window.enriched
