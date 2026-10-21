"""Bounded scan and hub finding-page selection."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import partial
from typing import Any

from agent_bom.api import compliance_hub_store, finding_cursor, findings_current
from agent_bom.api.finding_kev_total import exact_kev_total, exact_scoped_total
from agent_bom.api.finding_list_totals import fill_resume_total, resume_page_total
from agent_bom.api.finding_merge import MergedScanBulkPage as MergedScanBulkPage
from agent_bom.api.finding_merge import _merged_scan_bulk_page as _merged_scan_bulk_page
from agent_bom.api.finding_merge import _resolve_bulk_findings_total as _resolve_bulk_findings_total
from agent_bom.api.finding_page_query import _FindingListPage, _FindingListQuery
from agent_bom.api.finding_read_context import read_once
from agent_bom.api.finding_scope_filters import _finding_sort_key as _finding_sort_key
from agent_bom.api.finding_scope_filters import _row_matches_scope as _row_matches_scope
from agent_bom.api.finding_walk_cache import walk_rows as _walk_scan_rows
from agent_bom.api.scan_finding_read import _bulk_ingested_findings_for_tenant as _bulk_ingested_findings_for_tenant
from agent_bom.api.scan_finding_read import _completed_jobs_for_tenant as _completed_jobs_for_tenant
from agent_bom.api.scan_finding_read import _current_scan_rows as _current_scan_rows
from agent_bom.api.scan_finding_read import scan_rows_inputs
from agent_bom.api.stores import _get_store


def _filter_finding_rows(rows: list[dict[str, Any]], query: _FindingListQuery) -> list[dict[str, Any]]:
    """Apply severity, lifecycle status and scope filters to in-memory rows."""
    if query.severity:
        normalized = query.severity.lower()
        rows = [item for item in rows if str(item.get("severity", "")).lower() == normalized]
    # Scan findings carry no lifecycle status, so they count as ``open``.
    rows = [item for item in rows if compliance_hub_store.status_matches(item, query.status_key)]
    if query.scope_filters:
        rows = [item for item in rows if _row_matches_scope(item, query.scope_filters)]
    return rows


def _row_inputs(query: _FindingListQuery, job_store: Any) -> tuple[tuple[str, ...], float | None] | None:
    """Fingerprint the scan half's non-job inputs so a first page can reuse a prior rebuild."""
    return scan_rows_inputs(query.tenant_id, query.window_since, job_store)


def _scan_half_rows(query: _FindingListQuery, store: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Current-state scan findings for the page, sorted for the merged walk.

    The default view collapses re-scans to the current state per finding;
    ``?scan_id=`` returns that scan's rows verbatim.
    """
    if query.cursor and query.merged_cursor is None:
        # A plain hub keyset cursor: the scan half was delivered on earlier
        # merged pages, so skip the O(all-completed-jobs) fold entirely.
        if _completed_jobs_for_tenant(query.tenant_id):
            warnings.append("cursor pagination applies to bulk-ingested findings only; in-memory scan findings appear on the first page")
        return []

    def load() -> list[dict[str, Any]]:
        rows = _current_scan_rows(query.tenant_id, query.window_since, query.scan_id)
        rows = findings_current.scan_only_findings(rows, query.tenant_id, hub=store, scan_id=query.scan_id)
        rows = _filter_finding_rows(rows, query)
        rows.sort(key=lambda row: _finding_sort_key(row, query.sort_key))
        return rows

    # View filters and issue grouping page through up to 50k rows in one read;
    # fold, filter and sort the scan half once per read instead of once per page.
    # Callers only index into or copy the returned list.
    key = [query.tenant_id, query.window_since, query.scan_id, query.severity, query.status_key, query.sort_key]
    walk_key = (query.window_days, *key[2:], json.dumps(sorted(query.scope_filters.items())))
    continuation = query.merged_cursor is not None
    job_store = _get_store()
    inputs = partial(_row_inputs, query, job_store)
    walk = partial(
        _walk_scan_rows, walk_key, tenant_id=query.tenant_id, hub=store, job_store=job_store, continuation=continuation, inputs=inputs
    )
    return read_once(("scan_half_rows", json.dumps([*key, sorted(query.scope_filters.items())])), lambda: walk(load=load))


def _merged_page_next_cursor(query: _FindingListQuery, page: MergedScanBulkPage) -> str | None:
    if not page.has_more:
        return None
    return finding_cursor.encode_merged_scan_cursor(sort=query.sort_key, scan_index=page.next_scan_index, bulk_cursor=page.next_bulk_cursor)


def _merged_page(
    query: _FindingListQuery,
    scan_findings: list[dict[str, Any]],
    bulk_list: Callable[..., Any],
    **scope_kwargs: Any,
) -> tuple[list[dict[str, Any]], str | None]:
    merged = _merged_scan_bulk_page(
        scan_findings,
        bulk_list=bulk_list,
        tenant_id=query.tenant_id,
        sort_key=query.sort_key,
        severity=query.severity,
        scan_id=query.scan_id,
        offset=query.offset,
        limit=query.limit,
        scan_start=query.scan_start,
        bulk_cursor=query.bulk_cursor_in,
        since=query.window_since,
        status=query.status_key,
        **scope_kwargs,
    )
    return merged.rows, _merged_page_next_cursor(query, merged)


def _bulk_page(query: _FindingListQuery, bulk_list: Callable[..., Any], **kwargs: Any) -> tuple[list[dict[str, Any]], Any, str | None]:
    """One keyset/offset page from the hub's bulk-ingest source."""
    params = {
        "limit": query.limit,
        "offset": 0 if query.cursor else query.offset,
        "sort": query.sort_key,
        "severity": query.severity,
        "scan_id": query.scan_id,
        "origin": "bulk_ingest",
        "cursor": query.bulk_cursor_in,
        "since": query.window_since,
        "status": query.status_key,
        **kwargs,
    }
    result = bulk_list(query.tenant_id, **params)
    return result[0], result[1], (result[2] if len(result) > 2 else None)


def _in_memory_findings_page(query: _FindingListQuery, scan_findings: list[dict[str, Any]]) -> _FindingListPage:
    """Store without keyset paging: materialize, sort and walk by index.

    The merged cursor's ``scan_index`` slot doubles as the index so
    ``has_more`` stays honest and the rest is retrievable.
    """
    bulk_findings = _bulk_ingested_findings_for_tenant(query.tenant_id)
    if query.scan_id:
        bulk_findings = [item for item in bulk_findings if str(item.get("scan_id") or "") == query.scan_id]
    combined = scan_findings + _filter_finding_rows(bulk_findings, query)
    combined.sort(key=lambda row: _finding_sort_key(row, query.sort_key))
    start = query.scan_start if query.merged_cursor is not None else query.offset
    rows = combined[start : start + query.limit]
    end = start + len(rows)
    next_cursor = (
        finding_cursor.encode_merged_scan_cursor(sort=query.sort_key, scan_index=end, bulk_cursor="") if end < len(combined) else None
    )
    return _FindingListPage(rows=rows, total=len(combined), total_approximate=False, next_cursor=next_cursor)


def _findings_page(
    query: _FindingListQuery,
    scan_findings: list[dict[str, Any]],
    store: Any,
    scope_metadata: dict[str, Any],
) -> _FindingListPage:
    """Read one page, then resolve its totals under the same query contract."""
    current = getattr(store, "list_current_page", None)
    bulk_list = current or getattr(store, "list_page", None)
    if not callable(bulk_list) or (query.scope_filters and not callable(current)):
        return _in_memory_findings_page(query, scan_findings)

    scoped = bool(query.scope_filters)
    merged = callable(current) and (query.merged_cursor is not None or (not query.cursor and bool(scan_findings)))
    extra = {"scope": dict(query.scope_filters), "scope_metadata": scope_metadata} if scoped else {}
    bulk_total = None
    if merged:
        if not scoped and query.merged_cursor is None:
            _, bulk_total, _ = _bulk_page(query, bulk_list, limit=1, offset=0, cursor=None, include_total=query.include_bulk_total)
        rows, next_cursor = _merged_page(query, scan_findings, bulk_list, **extra)
    else:
        rows, bulk_total, next_cursor = _bulk_page(query, bulk_list, include_total=not scoped and query.include_bulk_total, **extra)

    if scoped:
        total = exact_kev_total(query, len(scan_findings), bulk_list, compliance_hub_store.get_compliance_hub_store())
        if total is None:
            total = exact_scoped_total(query, len(scan_findings), bulk_list)
        approximate = total is None
    elif merged and query.merged_cursor is not None:
        total, approximate = resume_page_total(query, bulk_list, scan_count=len(scan_findings))
    else:
        total, approximate = _resolve_bulk_findings_total(
            tenant_id=query.tenant_id,
            severity=query.severity,
            scan_id=query.scan_id,
            approximate_total=query.approximate_total,
            offset=0 if query.cursor else query.offset,
            bulk_total=bulk_total,
            request_cached_total=query.cached_bulk_total,
            page_len=len(rows),
            limit=query.limit,
            window_days=query.window_days,
            status=query.status_key,
        )
        if merged:
            total = None if total is None else len(scan_findings) + total
        else:
            total, approximate = fill_resume_total(query, bulk_list, total, approximate)
    return _FindingListPage(rows=rows, total=total, total_approximate=approximate, next_cursor=next_cursor)
