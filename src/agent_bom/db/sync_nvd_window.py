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
    _read_sync_metadata,
    _update_sync_meta,
    _upsert_cpe_matches,
    _upsert_nvd_enrichment_row,
    _validate_sync_url,
)
from agent_bom.db.sync_nvd_coverage import Interval, Resume, load_covered, load_resume, merge, nvd_ts, plan, resume_index
from agent_bom.db.sync_parsing import _extract_nvd_cpe_matches, _extract_nvd_cve_fields

NVD_WINDOW_SECONDS = 30.0
NVD_ANONYMOUS_REQUESTS_PER_WINDOW = 5
NVD_KEYED_REQUESTS_PER_WINDOW = 50
# NVD caps a lastModified range at 120 days; keyless runs stay short enough to
# finish in a few pages at 5 requests per 30 seconds.
KEYED_LOOKBACK_DAYS = 120
KEYLESS_LOOKBACK_DAYS = 14
NVD_PAGE_SIZE = 2000
# Thirty pages, about three minutes at the anonymous budget. A live two-week
# window held about 50,000 modified CVEs (11,209 in three days on 2026-10-24),
# so a keyless run from scratch usually finishes in one pass.
KEYLESS_MAX_RECORDS = 60_000


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
class _Run:
    """One window run: the request budget left and what it reached."""

    remaining: float
    covered: list[Interval]
    fetched: int = 0
    new_rows: int = 0
    resume: Resume | None = None
    partial_reason: str | None = None


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


def _ingest_page(conn: sqlite3.Connection, items: list[Any], run: _Run) -> None:
    for item in items:
        cve_data = item.get("cve") if isinstance(item, dict) else None
        run.fetched += 1
        run.remaining -= 1
        if isinstance(cve_data, dict) and str(cve_data.get("id") or "").startswith("CVE-") and _upsert_nvd_cve(conn, cve_data):
            run.new_rows += 1
    conn.commit()


def _page_slice(conn: sqlite3.Connection, query: _Query, piece: Interval, start_index: int, run: _Run) -> bool:
    """Page one slice; ``True`` when every record in it was read."""
    index = start_index
    while run.remaining > 0:
        params = {
            "lastModStartDate": nvd_ts(piece[0]),
            "lastModEndDate": nvd_ts(piece[1]),
            "resultsPerPage": int(min(query.page_size, run.remaining)),
            "startIndex": index,
        }
        try:
            data = fetch_nvd_page(f"{query.base_url}?{urllib.parse.urlencode(params)}", query.headers, query.limiter)
        except NvdWindowError as exc:
            _logger.warning("NVD window sync stopped in slice %s..%s: %s", params["lastModStartDate"], params["lastModEndDate"], exc.reason)
            run.partial_reason = exc.reason
            run.resume = Resume(piece[0], piece[1], index) if index else None
            return False
        items = data.get("vulnerabilities") or []
        _ingest_page(conn, items, run)
        index += len(items)
        if not items or index >= int(data.get("totalResults") or 0):
            return True
    run.partial_reason = "truncated"
    run.resume = Resume(piece[0], piece[1], index)
    return False


@dataclass(frozen=True)
class _Query:
    base_url: str
    headers: dict[str, str]
    limiter: NvdRateLimiter
    page_size: int = NVD_PAGE_SIZE


def _walk(conn: sqlite3.Connection, query: _Query, pieces: list[Interval], resume: Resume | None, run: _Run) -> None:
    for piece in pieces:
        if not _page_slice(conn, query, piece, resume_index(resume, piece, query.page_size), run):
            return
        run.covered.append(piece)


def _record(
    conn: sqlite3.Connection, run: _Run, window: Interval, *, lookback_days: int, max_results: int | None, api_key_used: bool
) -> None:
    floor, now = window
    covered = merge(run.covered, floor)
    partial = run.partial_reason is not None
    complete = covered == [(floor, now)]
    _update_sync_meta(
        conn,
        "nvd",
        run.new_rows,
        {
            "mode": "incremental",
            "status": "partial" if partial else "synced",
            "partial_reason": run.partial_reason,
            "lookback_days": lookback_days,
            "covered": [[nvd_ts(start), nvd_ts(end)] for start, end in covered],
            "resume": run.resume.to_meta() if run.resume else None,
            "records_fetched": run.fetched,
            "new_rows": run.new_rows,
            "last_modified_start": nvd_ts(floor),
            # The synced-through cursor reaches ``now`` only when the whole
            # window is held, so a capped or failed run is never read as synced.
            "last_modified_end": nvd_ts(now) if complete and not partial else nvd_ts(floor),
            "max_results": max_results,
            "api_key_used": api_key_used,
            "sync_failed": partial and run.partial_reason != "truncated",
            "sync_truncated": run.partial_reason == "truncated",
        },
    )


def default_max_results(api_key: str | None) -> int | None:
    """Keyed runs cover the whole window; keyless runs stay bounded (still newest first)."""
    return None if api_key else KEYLESS_MAX_RECORDS


def sync_nvd_incremental(
    conn: sqlite3.Connection,
    nvd_api_key: Optional[str] = None,
    url: Optional[str] = None,
    max_results: Optional[int] = None,
    lookback_days: Optional[int] = None,
    limiter: Optional[NvdRateLimiter] = None,
) -> int:
    """Ingest CVEs NVD published or modified in a bounded window, newest first, CPE ranges included.

    The window (120 days keyed, 14 keyless) is walked in day slices from now
    backwards and only ranges not already covered are fetched. ``max_results``
    caps records read this run (default: unbounded with a key, 60,000
    without). A rate-limited, timed-out or capped run is ``status: partial``
    and the next run resumes where it stopped. Returns new CVE rows.
    """
    base_url = url or _NVD_API_URL
    _validate_sync_url(base_url, "nvd url")
    days = lookback_days or (KEYED_LOOKBACK_DAYS if nvd_api_key else KEYLESS_LOOKBACK_DAYS)
    cap = max_results if max_results is not None else default_max_results(nvd_api_key)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    floor = now - timedelta(days=days)
    meta = _read_sync_metadata(conn, "nvd")
    covered, resume = merge(load_covered(meta), floor), load_resume(meta)
    headers = {"Accept": "application/json", **({"apiKey": nvd_api_key} if nvd_api_key else {})}
    query = _Query(base_url, headers, limiter or NvdRateLimiter.for_key(nvd_api_key), min(NVD_PAGE_SIZE, cap or NVD_PAGE_SIZE))
    run = _Run(remaining=float(cap) if cap is not None else float("inf"), covered=list(covered))
    _walk(conn, query, plan(floor, now, covered, resume), resume, run)
    conn.commit()
    _record(conn, run, (floor, now), lookback_days=days, max_results=cap, api_key_used=bool(nvd_api_key))
    _logger.info("NVD window sync %s: %d records read, %d new CVE rows", run.partial_reason or "complete", run.fetched, run.new_rows)
    return run.new_rows
