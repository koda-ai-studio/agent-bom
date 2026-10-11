"""Finding merge."""

from __future__ import annotations

from collections.abc import Callable, Mapping
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
    if not approximate_total:
        if bulk_total is not None:
            set_cached_total(key, bulk_total)
            return bulk_total, False
        cached = get_cached_total(key)
        if cached is None:
            cached = request_cached_total
        if cached is not None:
            # Cache entries are populated only from an exact store COUNT.  A
            # normal request reusing that value remains complete; labelling it
            # approximate made the campaign workflow reject a second request
            # as provisional even though the underlying membership was exact.
            return cached, False
        return bulk_total, False

    if offset == 0 and bulk_total is not None:
        set_cached_total(key, bulk_total)
        return bulk_total, False

    cached = get_cached_total(key)
    if cached is None:
        cached = request_cached_total
    if cached is not None:
        return cached, True

    # Cold cache on a deep page: expose a conservative lower bound so paging
    # controls stay usable until the client revisits offset=0.
    if page_len < limit:
        return offset + page_len, True
    return offset + limit, True


_BULK_MERGE_CHUNK = 256


class MergedScanBulkPage(NamedTuple):
    """A merged page plus the frontier needed to resume the keyset walk.

    ``next_scan_index`` is how many pre-sorted scan findings have been consumed
    (skipped + emitted); ``next_bulk_cursor`` is the hub keyset cursor of the
    last consumed bulk row (``""`` when no bulk row was consumed). Together they
    let ``/v1/findings`` emit ONE compound cursor so a keyset caller walks the
    full merged set with 0 dups / 0 drops instead of losing the scan half after
    page 1.
    """

    rows: list[dict[str, Any]]
    next_scan_index: int
    next_bulk_cursor: str
    has_more: bool


class _ScanBulkMerge:
    """Two-pointer walk over pre-sorted scan findings and keyset-refilled hub pages.

    Each source is consumed strictly in order, so a page consumes a contiguous
    prefix of each source after its resume point.
    """

    def __init__(
        self,
        scan_findings: list[dict[str, Any]],
        fetch_bulk: Callable[[str | None], Any],
        *,
        sort_key: str,
        scan_start: int,
        bulk_cursor: str | None,
    ) -> None:
        self.scan_findings = scan_findings
        self.sort_key = sort_key
        self.scan_i = scan_start
        self.bulk_buf: list[dict[str, Any]] = []
        self.bulk_i = 0
        self.last_bulk_consumed: dict[str, Any] | None = None
        self._fetch_bulk = fetch_bulk
        self._fetch_cursor: str | None = bulk_cursor or None
        self._bulk_exhausted = False

    def _refill_bulk(self) -> bool:
        if self._bulk_exhausted:
            self.bulk_buf = []
            self.bulk_i = 0
            return False
        result = self._fetch_bulk(self._fetch_cursor)
        self.bulk_buf = result[0]
        self._fetch_cursor = result[2] if len(result) > 2 else None
        if not self._fetch_cursor:
            self._bulk_exhausted = True
        self.bulk_i = 0
        return bool(self.bulk_buf)

    def bulk_head(self) -> dict[str, Any] | None:
        if self.bulk_i >= len(self.bulk_buf) and not self._refill_bulk():
            return None
        return self.bulk_buf[self.bulk_i]

    def scan_head(self) -> dict[str, Any] | None:
        return self.scan_findings[self.scan_i] if self.scan_i < len(self.scan_findings) else None

    def _take_scan(self) -> dict[str, Any]:
        row = self.scan_findings[self.scan_i]
        self.scan_i += 1
        return row

    def _take_bulk(self) -> dict[str, Any]:
        row = self.bulk_buf[self.bulk_i]
        self.bulk_i += 1
        self.last_bulk_consumed = row
        return row

    def pick_next(self) -> dict[str, Any] | None:
        scan_row = self.scan_head()
        bulk_row = self.bulk_head()
        if scan_row is None and bulk_row is None:
            return None
        if bulk_row is None:
            return self._take_scan()
        if scan_row is None:
            return self._take_bulk()
        if _finding_sort_key(scan_row, self.sort_key) <= _finding_sort_key(bulk_row, self.sort_key):
            return self._take_scan()
        return self._take_bulk()

    def has_more(self) -> bool:
        return self.scan_head() is not None or self.bulk_head() is not None


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
    """Merge pre-sorted scan findings with bulk hub pages without O(table) work.

    Streams two sorted sources with a two-pointer walk so deep ``offset`` does
    not require loading ``offset + limit`` bulk rows up front or re-sorting the
    full combined window in memory. The bulk source is refilled by keyset cursor
    (``list_current_page``) so the merge stays sargable and — critically — the
    frontier it stops at is expressible as one resumable cursor. ``scan_start``
    (index into ``scan_findings``) and ``bulk_cursor`` (hub keyset position)
    resume a prior page; ``status`` filters the bulk source's lifecycle status
    to match the merged scan findings' basis (default open) so both halves
    reconcile.

    Each source is consumed strictly in order (scan by ascending index, bulk in
    the store's keyset order), so a page consumes a contiguous prefix of each
    source after its resume point — that is what makes the walk drop-free and
    dup-free regardless of the merge comparator's tiebreakers.
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

    walk = _ScanBulkMerge(scan_findings, fetch_bulk, sort_key=sort_key, scan_start=scan_start, bulk_cursor=bulk_cursor)
    skipped = 0
    while skipped < offset and walk.pick_next() is not None:
        skipped += 1
    page: list[dict[str, Any]] = []
    while len(page) < limit and (row := walk.pick_next()) is not None:
        page.append(row)
    has_more = walk.has_more()
    if walk.last_bulk_consumed is not None:
        next_bulk_cursor = finding_cursor.cursor_from_current_row(walk.last_bulk_consumed, sort=sort_key)
    else:
        next_bulk_cursor = bulk_cursor or ""
    return MergedScanBulkPage(page, walk.scan_i, next_bulk_cursor, has_more)
