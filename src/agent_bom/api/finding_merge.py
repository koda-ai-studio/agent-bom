"""Finding merge."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from heapq import merge
from typing import Any, NamedTuple

from agent_bom.api import finding_cursor
from agent_bom.api.finding_scope_filters import _finding_sort_key as _finding_sort_key


def _resolve_bulk_findings_total(
    *,
    tenant_id: str,
    severity: str | None,
    scan_id: str | None,
    approximate_total: bool,
    offset: int,
    bulk_total: int | None,
    page_len: int,
    limit: int,
    window_days: int = 0,
    status: str | None = None,
    request_cached_total: int | None = None,
) -> tuple[int | None, bool]:
    """Return ``(total, total_approximate)`` for the bulk-ingest slice."""
    from agent_bom.api.findings_count_cache import cache_key, get_cached_total, set_cached_total

    # Preserve the count that justified skipping COUNT at request start. It may
    # expire while scan rows are assembled; using the snapshot does not renew TTL.
    key = cache_key(tenant_id=tenant_id, severity=severity, scan_id=scan_id, origin="bulk_ingest", window_days=window_days, status=status)
    if bulk_total is not None and (not approximate_total or offset == 0):
        set_cached_total(key, bulk_total)
        return bulk_total, False

    cached = get_cached_total(key)
    if cached is None:
        cached = request_cached_total
    if cached is not None or not approximate_total:
        # Normal reads retain the exact-count contract; only callers opting
        # into approximate totals label a reused count approximate.
        return cached, bool(approximate_total)

    # Cold approximate reads expose a lower bound until offset=0 is counted.
    return offset + min(page_len, limit), True


_BULK_MERGE_CHUNK = 256


class MergedScanBulkPage(NamedTuple):
    """A merged page plus the frontier needed to resume the keyset walk.

    ``next_scan_index`` is how many pre-sorted scan findings have been consumed
    (skipped + emitted); ``next_bulk_cursor`` is the hub keyset cursor of the
    last consumed bulk row, or a bounded scope walk's checkpoint. Together they
    let ``/v1/findings`` emit ONE compound cursor so a keyset caller walks the
    full merged set with 0 dups / 0 drops instead of losing the scan half after
    page 1.
    """

    rows: list[dict[str, Any]]
    next_scan_index: int
    next_bulk_cursor: str
    has_more: bool


class _MergeInput(NamedTuple):
    row: dict[str, Any] | None
    scan_index: int | None = None
    bulk_cursor: str = ""


def _bulk_inputs(fetch: Callable[[str | None], Any], cursor: str | None) -> Iterator[_MergeInput]:
    while True:
        result = fetch(cursor)
        rows = result[0]
        cursor = result[2] if len(result) > 2 else None
        for row in rows:
            yield _MergeInput(row)
        if not cursor:
            return
        if not rows:
            # A bounded scope walk can advance without finding a match. Pause
            # both sources: the next bulk head could outrank the next scan row.
            yield _MergeInput(None, bulk_cursor=cursor)
            return


def _merge_input_key(item: _MergeInput, sort: str) -> tuple[float, float, float]:
    return _finding_sort_key(item.row, sort) if item.row is not None else (float("-inf"),) * 3


def _merge_bulk_kwargs(
    since: str | None, status: str | None, scope: Mapping[str, str] | None, scope_metadata: dict[str, Any] | None
) -> dict[str, Any]:
    extra: dict[str, Any] = {}
    if since:
        extra["since"] = since
    if status is not None:
        extra["status"] = status
    if scope:
        extra["scope"] = dict(scope)
        if scope_metadata is not None:
            # One dict across every refill: the store accumulates, so the merged
            # page reports the combined walk.
            extra["scope_metadata"] = scope_metadata
    return extra


def _merged_scan_bulk_page(
    scan_findings: list[dict[str, Any]],
    *,
    bulk_list: Any,
    tenant_id: str,
    sort_key: str,
    severity: str | None,
    scan_id: str | None,
    offset: int,
    limit: int,
    scan_start: int = 0,
    bulk_cursor: str | None = None,
    since: str | None = None,
    scope: Mapping[str, str] | None = None,
    status: str | None = None,
    scope_metadata: dict[str, Any] | None = None,
) -> MergedScanBulkPage:
    """Merge bounded bulk pages with sorted scans and retain consumed frontiers.

    The stable merge preserves each source's order and prefers scans on ties.
    Lookahead can fetch a row, but only emitted/skipped rows advance cursors.
    Empty scoped pages with a continuation pause the walk without losing the
    store's progress or reading beyond its budget.
    """
    extra_kwargs = _merge_bulk_kwargs(since, status, scope, scope_metadata)

    def fetch_bulk(cursor: str | None) -> Any:
        return bulk_list(
            tenant_id,
            limit=_BULK_MERGE_CHUNK,
            sort=sort_key,
            severity=severity,
            scan_id=scan_id,
            origin="bulk_ingest",
            include_total=False,
            cursor=cursor,
            **extra_kwargs,
        )

    scan_inputs = (_MergeInput(scan_findings[index], scan_index=index + 1) for index in range(scan_start, len(scan_findings)))
    stream = merge(scan_inputs, _bulk_inputs(fetch_bulk, bulk_cursor), key=lambda item: _merge_input_key(item, sort_key))
    page: list[dict[str, Any]] = []
    scan_index, next_bulk_cursor = scan_start, bulk_cursor or ""
    last_bulk: dict[str, Any] | None = None
    has_more = False
    for position, item in enumerate(stream):
        if item.row is None:
            # Everything before this boundary was consumed; no matching bulk
            # row was skipped between its last emitted row and this checkpoint.
            return MergedScanBulkPage(page, scan_index, item.bulk_cursor, True)
        if position >= offset + limit:
            has_more = True
            break
        if item.scan_index is None:
            last_bulk = item.row
        else:
            scan_index = item.scan_index
        if position >= offset:
            page.append(item.row)
    if last_bulk is not None:
        next_bulk_cursor = finding_cursor.cursor_from_current_row(last_bulk, sort=sort_key)
    return MergedScanBulkPage(page, scan_index, next_bulk_cursor, has_more)
