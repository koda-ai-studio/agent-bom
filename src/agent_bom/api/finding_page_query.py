"""Validated finding-page query and scope contracts."""

from __future__ import annotations

from typing import Any, NamedTuple

from fastapi import HTTPException, Request

from agent_bom.api import finding_cursor, findings_count_cache, time_window
from agent_bom.api.finding_list_envelope import HUB_LIST_OFFSET_CEILING as _HUB_LIST_OFFSET_CEILING
from agent_bom.api.finding_list_helpers import (
    _ALLOWED_FINDING_SEVERITIES,
    _ALLOWED_FINDING_STATUSES,
    _DEFAULT_FINDING_STATUS,
    _normalize_finding_sort,
)
from agent_bom.api.scan_request_context import _tenant_id
from agent_bom.finding_scope import canonical_finding_severity_filter
from agent_bom.security import sanitize_error


class _FindingListQuery(NamedTuple):
    """Validated, tenant-scoped parameters for one ``/v1/findings`` page."""

    tenant_id: str
    sort_key: str
    severity: str | None
    status_key: str
    scan_id: str | None
    limit: int
    offset: int
    cursor: str | None
    merged_cursor: tuple[int, str] | None
    window_days: int
    window_since: str | None
    scope_filters: dict[str, str]
    approximate_total: bool
    cached_bulk_total: int | None
    include_bulk_total: bool

    @property
    def scan_start(self) -> int:
        return self.merged_cursor[0] if self.merged_cursor is not None else 0

    @property
    def bulk_cursor_in(self) -> str | None:
        # A compound merged cursor carries the hub keyset position; a plain
        # cursor carries only the hub position (the scan half was delivered).
        return (self.merged_cursor[1] or None) if self.merged_cursor is not None else self.cursor


class _FindingListPage(NamedTuple):
    rows: list[dict[str, Any]]
    total: int | None
    total_approximate: bool
    next_cursor: str | None


def _validated_finding_list_params(
    sort: str, severity: str | None, status: str, cursor: str | None, offset: int
) -> tuple[str, str | None, str, tuple[int, str] | None]:
    """Reject bad list parameters with explicit 4xx errors.

    Silently falling back made typos read as "no findings" or "wrong order".
    """
    sort_key = _normalize_finding_sort(sort)
    try:
        severity = canonical_finding_severity_filter(severity)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"invalid severity; accepted values: {', '.join(_ALLOWED_FINDING_SEVERITIES)}",
        ) from None
    status_key = status.strip().lower() if isinstance(status, str) else _DEFAULT_FINDING_STATUS
    if status_key not in _ALLOWED_FINDING_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"invalid status '{status}'; accepted values: {', '.join(_ALLOWED_FINDING_STATUSES)}",
        )
    if cursor and offset:
        raise HTTPException(status_code=400, detail="cursor and offset are mutually exclusive")
    if offset > _HUB_LIST_OFFSET_CEILING:
        # Deep OFFSET scans linearly; cursor pagination is the unbounded-depth contract.
        raise HTTPException(
            status_code=400,
            detail=f"offset exceeds ceiling {_HUB_LIST_OFFSET_CEILING}; use cursor pagination for deeper walks",
        )
    # A cursor is either a compound merged token (scan + hub frontier) or a plain
    # hub keyset cursor. Decode the compound form first so a keyset caller
    # resuming the scan half is routed to the merged walk.
    merged_cursor: tuple[int, str] | None = None
    if cursor:
        try:
            merged_cursor = finding_cursor.decode_merged_scan_cursor(cursor, expected_sort=sort_key)
            if merged_cursor is None:
                finding_cursor.decode_finding_cursor(cursor, expected_sort=sort_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    return sort_key, severity, status_key, merged_cursor


def _finding_list_query(
    request: Request,
    *,
    sort: str,
    severity: str | None,
    status: str,
    scan_id: str | None,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    window_days: int | None,
) -> _FindingListQuery:
    tenant_id = _tenant_id(request)
    # Default read-window (~90d) bounds counts at scale; ``window_days=0`` widens to all history.
    resolved_window = time_window.normalize_window_days(window_days)
    window_since = time_window.window_since_iso(resolved_window)
    sort_key, severity, status_key, merged_cursor = _validated_finding_list_params(sort, severity, status, cursor, offset)
    effective_approximate_total = findings_count_cache.resolve_effective_approximate_total(
        requested=approximate_total,
        tenant_id=tenant_id,
        severity=severity,
        scan_id=scan_id,
        window_days=resolved_window,
        status=status_key,
    )
    cached_bulk_total = findings_count_cache.get_cached_total(
        findings_count_cache.cache_key(
            tenant_id=tenant_id,
            severity=severity,
            scan_id=scan_id,
            origin="bulk_ingest",
            window_days=resolved_window,
            status=status_key,
        )
    )
    approximate = bool(approximate_total or effective_approximate_total)
    # Approximate reads reuse cached totals; warm the cache with one exact count
    # only when it is cold on the first page.
    include_bulk_total = not cursor and cached_bulk_total is None and (offset == 0 or not approximate)
    return _FindingListQuery(
        tenant_id=tenant_id,
        sort_key=sort_key,
        severity=severity,
        status_key=status_key,
        scan_id=scan_id,
        limit=limit,
        offset=offset,
        cursor=cursor,
        merged_cursor=merged_cursor,
        window_days=resolved_window,
        window_since=window_since,
        scope_filters={},
        approximate_total=approximate,
        cached_bulk_total=cached_bulk_total,
        include_bulk_total=include_bulk_total,
    )
