"""Exact totals for ``GET /v1/findings`` resume (cursor) pages.

Page one counts the bulk-ingest slice once and caches it per tenant + filter
set. A resume page reuses that exact count, or runs the same single COUNT when
the cache is cold, so every page of one walk reports the same denominator.
Approximate reads never pay for a count; they keep the honest unknown marker.
"""

from __future__ import annotations

from typing import Any, Callable

from agent_bom.api import findings_count_cache


def _cache_key(query: Any) -> tuple[Any, ...]:
    return findings_count_cache.cache_key(
        tenant_id=query.tenant_id,
        severity=query.severity,
        scan_id=query.scan_id,
        origin="bulk_ingest",
        window_days=query.window_days,
        status=query.status_key,
    )


def _count_bulk(query: Any, bulk_list: Callable[..., Any]) -> int | None:
    probe = bulk_list(
        query.tenant_id,
        limit=1,
        offset=0,
        sort=query.sort_key,
        severity=query.severity,
        scan_id=query.scan_id,
        origin="bulk_ingest",
        include_total=True,
        since=query.window_since,
        status=query.status_key,
    )
    total = probe[1] if len(probe) > 1 else None
    return total if isinstance(total, int) and not isinstance(total, bool) else None


def bulk_total_for_resume(query: Any, bulk_list: Callable[..., Any]) -> tuple[int | None, bool]:
    """``(bulk_total, approximate)`` for one resume page of an unscoped query."""
    key = _cache_key(query)
    cached = findings_count_cache.get_cached_total(key)
    if cached is None:
        cached = query.cached_bulk_total
    if cached is not None:
        return cached, bool(query.approximate_total)
    if query.approximate_total:
        return None, True
    counted = _count_bulk(query, bulk_list)
    if counted is not None:
        findings_count_cache.set_cached_total(key, counted)
    return counted, False


def resume_page_total(query: Any, bulk_list: Callable[..., Any], *, scan_count: int) -> tuple[int | None, bool]:
    """``(total, approximate)`` for a resume page: the scan half plus the bulk slice."""
    bulk, approximate = bulk_total_for_resume(query, bulk_list)
    return (None, True) if bulk is None else (scan_count + bulk, approximate)


def fill_resume_total(query: Any, bulk_list: Callable[..., Any], total: int | None, approximate: bool) -> tuple[int | None, bool]:
    """Keep a known total; otherwise give a bulk-only resume page its exact count."""
    if total is not None or not query.cursor:
        return total, approximate
    return resume_page_total(query, bulk_list, scan_count=0)
