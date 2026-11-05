"""Finding projections, facets and group response construction."""

from __future__ import annotations

from functools import partial
from typing import Any

from fastapi import Request

from agent_bom.api import compliance_hub_store, finding_cursor, time_window
from agent_bom.api import finding_reachability_prewarm as _finding_reachability_prewarm
from agent_bom.api.finding_facets import _finding_facets_bounded as _finding_facets_bounded
from agent_bom.api.finding_group_key import _finding_group_identity
from agent_bom.api.finding_grouping import _attach_grouping_metadata as _attach_grouping_metadata
from agent_bom.api.finding_grouping import _collect_group_occurrences as _collect_group_occurrences
from agent_bom.api.finding_grouping import _finding_group_offset as _finding_group_offset
from agent_bom.api.finding_grouping import _group_occurrence_rows as _group_occurrence_rows
from agent_bom.api.finding_grouping import _groups_envelope as _groups_envelope
from agent_bom.api.finding_grouping import attach_lane_counts, lane_severity_counts, select_group_lane
from agent_bom.api.finding_list_envelope import finding_list_envelope
from agent_bom.api.finding_list_helpers import _DEFAULT_FINDING_STATUS, _normalize_finding_sort, _serialize_finding_group
from agent_bom.api.finding_list_projection import project_list_row
from agent_bom.api.finding_page_filters import _findings_page, _scan_half_rows
from agent_bom.api.finding_page_query import _finding_list_query, _FindingListPage, _FindingListQuery
from agent_bom.api.finding_reachability import project_persisted_graph_reachability
from agent_bom.api.finding_read_context import finding_read_snapshot
from agent_bom.api.finding_scope_filters import _canonical_scope_filters as _canonical_scope_filters
from agent_bom.api.finding_scope_filters import _finding_list_filters as _finding_list_filters
from agent_bom.api.finding_suppression import project_current_suppressions
from agent_bom.api.finding_view_filters import _view_envelope as _view_envelope
from agent_bom.api.finding_view_filters import _view_filtered_row as _view_filtered_row
from agent_bom.api.finding_view_filters import _view_filters as _view_filters
from agent_bom.api.finding_view_filters import _walk_view_filtered_findings as _walk_view_filtered_findings
from agent_bom.api.finding_view_filters import redact_emitted_rows, redacts_after_filter
from agent_bom.api.hub_reference_payload import payload_is_kev
from agent_bom.api.scan_request_context import _logger, _tenant_id
from agent_bom.api.storage.finding_current_reads import issue_rank_band
from agent_bom.api.storage.finding_materialized import group_id_for_key
from agent_bom.api.stores import _get_graph_store
from agent_bom.core.estate_read_boundary import estate_read_boundary
from agent_bom.core.severity import severity_rank
from agent_bom.security import sanitize_error, sanitize_text

# Importing the reader surface registers its bounded graph-commit warm-up.
__all__ = ["_finding_reachability_prewarm"]


def _redact_finding_page(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from agent_bom.finding_scope import safe_finding_response_payload

    return [safe_finding_response_payload(project_list_row(row)) for row in rows]


def _project_findings_reachability(
    rows: list[dict[str, Any]],
    *,
    tenant_id: str,
    scan_id: str | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Project persisted paths once for the rows the caller will return.

    Grouped findings walk the occurrence stream in bounded pages. Projecting
    the same persisted graph against every internal 1,000-row page made an
    otherwise linear grouping request pay the graph-join cost dozens of times.
    Callers may now defer this helper until after grouping/pagination, so only
    the visible issue rows receive reachability enrichment.
    """
    warnings: list[str] = []
    try:
        with estate_read_boundary():
            projection = project_persisted_graph_reachability(
                rows,
                graph_store=_get_graph_store(),
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
        if projection.refreshing:
            warnings.append("The current graph is being prepared; graph reachability remains unassessed for this page.")
        if projection.truncated:
            warnings.append(
                "Graph reachability projection is bounded to the highest-risk 200000 persisted paths; unmatched findings remain unassessed."
            )
        return projection.rows, warnings
    except Exception as exc:  # noqa: BLE001 — optional evidence must not fail the findings list
        _logger.warning("Finding graph reachability projection skipped: %s", sanitize_text(sanitize_error(exc)))
        warnings.append("Graph reachability evidence is unavailable for this page; unmatched findings remain unassessed.")
        return rows, warnings


def _apply_finding_facets(query: _FindingListQuery, page: _FindingListPage, warnings: list[str]) -> tuple[_FindingListPage, dict, dict]:
    facets, facet_total, completeness = _finding_facets_bounded(
        query.tenant_id,
        severity=query.severity,
        scan_id=query.scan_id,
        since=query.window_since,
        scope=query.scope_filters,
        status=query.status_key,
    )
    # A bounded walk is a lower bound; only a complete walk or an
    # aggregate-derived exact total may replace the list path's total.
    if completeness["status"] == "complete" or completeness["total_exact"]:
        page = page._replace(total=facet_total, total_approximate=not completeness["total_exact"])
    if completeness["status"] != "complete":
        bounded = sorted(name for name, state in completeness["dimensions"].items() if state == "bounded")
        warnings.append(
            "Facet counting stopped after "
            f"{completeness['scanned_rows']} scanned rows ({completeness['reason']}); "
            f"these facet counts are lower bounds, not totals: {', '.join(bounded)}."
        )
    return page, facets, completeness


def _scope_completeness(scope_metadata: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    truncated = bool(scope_metadata.get("truncated"))
    completeness = {
        "status": "partial" if truncated else "complete",
        "reason": str(scope_metadata.get("reason") or ""),
        "scanned_rows": int(scope_metadata.get("scanned_rows") or 0),
        "scan_budget": int(scope_metadata.get("scan_budget") or 0),
    }
    if truncated:
        warnings.append(
            "Scope filter matching stopped after "
            f"{completeness['scanned_rows']} scanned rows ({completeness['reason']}); "
            "this page is partial — continue with next_cursor for the rest."
        )
    return completeness


def _attach_facets(envelope: dict[str, Any], facets: dict, completeness: dict) -> None:
    envelope["facets"] = facets
    envelope["facets_approximate"] = completeness["status"] != "complete"
    envelope["facet_metadata"] = {
        "domain": {"basis": "multi_label", "sums_to_total": False},
        "freshness": {
            "basis": ["last_observed", "last_seen"],
            "thresholds_hours": [24, 168, 720],
            "missing_or_invalid": "unavailable",
        },
        "completeness": completeness,
    }


def _findings_page_envelope(
    query: _FindingListQuery,
    page: _FindingListPage,
    rows: list[dict[str, Any]],
    *,
    filters: dict[str, Any],
    warnings: list[str],
    walk_truncated: bool = False,
) -> dict[str, Any]:
    total, total_approximate = page.total, page.total_approximate
    if total is None and not (page.next_cursor or query.cursor or query.offset or walk_truncated):
        # A first page with no continuation saw every match, so its size is exact.
        total, total_approximate = len(page.rows), False
    envelope = finding_list_envelope(
        findings=rows,
        total=total,
        limit=query.limit,
        offset=0 if query.cursor else query.offset,
        sort=query.sort_key,
        scan_id=query.scan_id,
        cursor=query.cursor or "",
        next_cursor=page.next_cursor or "",
        filters=filters,
        warnings=warnings,
        total_approximate=total_approximate,
        source="scan_and_current_ingest_findings",
        scope="tenant current-state findings",
    )
    # Echo the applied read-window so clients label counts as "last Nd", not "all".
    envelope["window"] = time_window.window_metadata(query.window_days)
    envelope["count_metadata"]["window"] = envelope["window"]
    return envelope


def _list_findings_impl(
    request: Request,
    q: str | None,
    severity: str | None,
    scan_id: str | None,
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    include_facets: bool = False,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    project_graph_reachability: bool = True,
    redact_page: bool = True,
    lane: str | None = None,
) -> dict:
    """Synchronous body of :func:`list_findings` (runs in a worker thread).

    Default sort is ``effective_reach``; ``?sort=cvss`` and ``?sort=severity``
    give CVSS-only and severity-band ordering. ``?approximate_total=true`` (and
    tenants above ``AGENT_BOM_FINDINGS_APPROXIMATE_TOTAL_THRESHOLD``) reuse
    cached totals instead of ``COUNT(*)``. ``?cursor=`` resumes the keyset walk
    from a prior ``next_cursor`` and cannot be combined with ``offset``.
    """
    query = _finding_list_query(
        request,
        sort=sort,
        severity=severity,
        status=status,
        scan_id=scan_id,
        limit=limit,
        offset=offset,
        cursor=cursor,
        approximate_total=approximate_total,
        window_days=window_days,
    )
    scope_filters = _canonical_scope_filters(
        provider, account, environment, domain, finding_class, q, kev, framework, control, owner, sla, lane
    )
    query = query._replace(scope_filters=scope_filters)
    store = compliance_hub_store.get_compliance_hub_store()
    warnings: list[str] = []
    scope_metadata: dict[str, Any] = {}
    scan_findings = _scan_half_rows(query, store, warnings)
    page = _findings_page(query, scan_findings, store, scope_metadata)
    facet_result: tuple[dict, dict] | None = None
    if include_facets:
        page, facets, completeness = _apply_finding_facets(query, page, warnings)
        facet_result = (facets, completeness)
    rows = page.rows
    if project_graph_reachability:
        rows, reachability_warnings = _project_findings_reachability(rows, tenant_id=query.tenant_id, scan_id=scan_id)
        warnings.extend(reachability_warnings)
    scope_completeness = _scope_completeness(scope_metadata, warnings) if scope_filters and scope_metadata else None
    # Internal aggregate callers may defer the default-deny projection; public callers keep it.
    rows = project_current_suppressions(rows, query.tenant_id)
    envelope = _findings_page_envelope(
        query,
        page,
        _redact_finding_page(rows) if redact_page else rows,
        filters=_finding_list_filters(finding_class, q, framework, control, owner, sla, severity=query.severity, scope=scope_filters),
        warnings=warnings,
        walk_truncated=bool(scope_metadata.get("truncated")),
    )
    if scope_completeness is not None:
        envelope["scope_completeness"] = scope_completeness
    if facet_result is not None:
        _attach_facets(envelope, *facet_result)
    return envelope


@finding_read_snapshot
def _list_findings_view_impl(
    request: Request,
    q: str | None,
    severity: str | None,
    scan_id: str | None,
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    include_facets: bool = False,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    reachability: str | None = None,
    triage: str | None = None,
    project_graph_reachability: bool = True,
    redact_page: bool = True,
    lane: str | None = None,
    path_context: str | None = None,
) -> dict[str, Any]:
    """Apply evidence-backed view filters before pagination.

    Walk canonical keysets for derived reachability, triage and path context;
    filtering before pagination preserves occurrence IDs and complete pages.
    """
    query_kw = dict(q=q, severity=severity, scan_id=scan_id, sort=sort, window_days=window_days, finding_class=finding_class, kev=kev)
    scope_kw = dict(
        provider=provider, account=account, environment=environment, domain=domain, framework=framework, control=control, lane=lane
    )
    tail_kw = dict(owner=owner, sla=sla, project_graph_reachability=project_graph_reachability, redact_page=redact_page)
    common: dict[str, Any] = {**query_kw, **scope_kw, **tail_kw}
    suppressed_only = status.strip().lower() == "suppressed"
    if path_context is None and reachability is None and triage is None and not suppressed_only:
        return _list_findings_impl(
            request,
            limit=limit,
            offset=offset,
            cursor=cursor,
            approximate_total=approximate_total,
            status=status,
            include_facets=include_facets,
            **common,
        )

    from agent_bom.api.routes.enterprise_routes.findings import build_tenant_triage_state_index

    def fetch_page(page_limit: int, source_cursor: str | None) -> dict[str, Any]:
        # ``open`` excludes suppressed evidence, so the suppressed view walks every lifecycle row.
        page_status = "all" if suppressed_only else status
        return _list_findings_impl(
            request,
            limit=page_limit,
            offset=0,
            cursor=source_cursor,
            approximate_total=True,
            status=page_status,
            include_facets=False,
            **{**common, "redact_page": redact_page and not redact_after_filter},
        )

    triage_index = build_tenant_triage_state_index(_tenant_id(request)) if triage is not None else None
    redact_after_filter = redacts_after_filter(redact_page=redact_page, triage=triage, triage_index=triage_index)
    view: dict[str, Any] = dict(triage_index=triage_index, reachability=reachability, triage=triage, suppressed_only=suppressed_only)
    row_filter = partial(_view_filtered_row, **view, path_context=path_context)
    walk = _walk_view_filtered_findings(fetch_page, row_filter, target=limit if cursor else offset + limit, cursor=cursor)
    walk = redact_emitted_rows(walk, _redact_finding_page) if redact_after_filter else walk
    filters = _view_filters(walk.first_page, suppressed_only=suppressed_only, reachability=reachability, triage=triage)
    if path_context is not None:
        filters["path_context"] = path_context
    return _view_envelope(walk, limit=limit, offset=offset, cursor=cursor, sort=sort, scan_id=scan_id, filters=filters)


@finding_read_snapshot
def _list_finding_groups_impl(
    request: Request,
    q: str | None,
    severity: str | None,
    scan_id: str | None,
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    approximate_total: bool,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    include_facets: bool = False,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    reachability: str | None = None,
    triage: str | None = None,
    lane: str | None = None,
    *,
    summary_only: bool = False,
    path_context: str | None = None,
) -> dict[str, Any]:
    """Build a bounded server-side issue queue over canonical occurrence rows.

    Group canonical occurrences by issue identity. ``summary_only`` omits
    facets and graph details without changing grouping or bounds.
    """
    sort_key = _normalize_finding_sort(sort)
    group_offset = _finding_group_offset(cursor, offset, sort_key)

    def fetch_page(budget: int, source_cursor: str | None, first: bool) -> dict[str, Any]:
        # Severity applies after grouping so the issue histogram stays
        # self-excluding: two occurrences of one advisory are one issue.
        head = (q, None, scan_id, sort_key, budget, 0, source_cursor, True, provider, account, environment, domain, window_days, status)
        occurrence_facets = include_facets and first and not summary_only
        tail = (finding_class, kev, occurrence_facets, framework, control, owner, sla, reachability, triage, False, False)
        return _list_findings_view_impl(request, *head, *tail, path_context=path_context)

    rows, first_page, warnings, source_cursor = _collect_group_occurrences(fetch_page)
    all_groups = _group_occurrence_rows(rows)
    normalized_severity = severity.strip().lower() if severity and severity.strip() else None
    groups, all_groups, counts_by_lane = select_group_lane(all_groups, normalized_severity, lane)
    truncated = source_cursor is not None
    if truncated:
        warnings.append("Issue grouping stopped after 50,000 occurrence rows; group and occurrence counts are lower bounds.")
    page_groups, reachability_warnings = _finding_group_page(
        [] if summary_only else groups[group_offset : group_offset + limit], tenant_id=_tenant_id(request), scan_id=scan_id
    )
    warnings.extend(reachability_warnings)
    next_offset = len(groups) if summary_only else group_offset + len(page_groups)
    next_cursor = finding_cursor.encode_finding_group_cursor(sort=sort_key, offset=next_offset) if next_offset < len(groups) else ""
    envelope = _groups_envelope(
        page_groups,
        first_page=first_page,
        total=len(groups),
        limit=limit,
        offset=0 if cursor else offset,
        sort=sort_key,
        scan_id=scan_id,
        cursor=cursor,
        next_cursor=next_cursor,
        warnings=warnings,
        severity=normalized_severity,
        truncated=truncated,
    )
    severity_counts = lane_severity_counts(all_groups, rows, lane) if include_facets else None
    _attach_grouping_metadata(
        envelope, first_page=first_page, groups=groups, scanned=len(rows), truncated=truncated, severity_counts=severity_counts
    )
    attach_lane_counts(envelope, lane, counts_by_lane, truncated, include_facets)
    _apply_exact_issue_counts(request, envelope, truncated, status=status, window_days=window_days, include_facets=include_facets)
    return envelope


def _finding_group_page(groups: list[dict[str, Any]], *, tenant_id: str, scan_id: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    if not groups:
        return [], []
    projected, warnings = _project_findings_reachability(groups, tenant_id=tenant_id, scan_id=scan_id)
    return [_serialize_finding_group(group) for group in projected], warnings


def _move(counts: dict[str, int], rank: int, delta: int) -> None:
    """Adjust one group's display band and, for unrated groups, its facet band."""
    counts[issue_rank_band(rank)] += delta
    if rank <= 1:
        counts["info" if rank == 1 else "unknown"] += delta


def _merge_scan_groups(counts: dict[str, int], scan_rows: list[dict[str, Any]], lookup: Any) -> dict[str, int]:
    """Fold scan occurrences in: a group already in the hub only moves to a worse band."""
    by_id = {group_id_for_key(_finding_group_identity(group)[1]): group for group in _group_occurrence_rows(scan_rows)}
    known = lookup(list(by_id)) if by_id else {}
    merged = dict(counts)
    for group_id, group in by_id.items():
        rank = severity_rank(str(group.get("severity") or "unknown"))
        kev = payload_is_kev(group)
        if group_id in known:
            hub_rank, hub_kev = known[group_id]
            if rank > hub_rank:
                _move(merged, hub_rank, -1)
                _move(merged, rank, 1)
            merged["kev"] += int(kev and not hub_kev)
            continue
        _move(merged, rank, 1)
        merged["total"] += 1
        merged["kev"] += int(kev)
    return merged


def exact_issue_counts(request: Request, *, status: str, window_days: int | None) -> dict[str, int] | None:
    """The default issue view's exact counts, or ``None`` when the store cannot answer them."""
    store = compliance_hub_store.get_compliance_hub_store()
    counter = getattr(store, "current_issue_group_counts", None)
    lookup = getattr(store, "current_issue_group_lookup", None)
    if not callable(counter) or not callable(lookup):
        return None
    query = _finding_list_query(
        request,
        sort="severity",
        severity=None,
        status=status,
        scan_id=None,
        limit=1,
        offset=0,
        cursor=None,
        approximate_total=True,
        window_days=window_days,
    )
    scope = {"origin": "bulk_ingest", "since": query.window_since, "status": query.status_key}
    hub = counter(query.tenant_id, **scope)
    if hub is None:
        return None
    return _merge_scan_groups(hub, _scan_half_rows(query, store, []), lambda ids: lookup(query.tenant_id, ids, **scope))


def issue_counts_block(counts: dict[str, int], *, window: dict[str, Any] | None) -> dict[str, Any]:
    block: dict[str, Any] = {key: int(counts.get(key) or 0) for key in ("critical", "high", "medium", "low", "unrated", "total", "kev")}
    block.update(approximate=False, window=window, basis="issue_groups")
    return block


def _apply_exact_issue_counts(
    request: Request, envelope: dict[str, Any], truncated: bool, *, status: str, window_days: int | None, include_facets: bool
) -> None:
    """Replace a bounded walk's lower bounds with exact totals; rows stay the paged window."""
    filters = {key: value for key, value in envelope["filters"].items() if value and key not in {"group_occurrences", "severity"}}
    if not truncated or filters or envelope.get("scan_id"):
        return
    counts = exact_issue_counts(request, status=status, window_days=window_days)
    severity = envelope["filters"].get("severity")
    total = None if counts is None else (counts["total"] if severity is None else counts.get(severity))
    if counts is None or total is None:
        return
    envelope["total"] = int(total)
    envelope.pop("total_approximate", None)
    envelope["count_metadata"].update(
        total=int(total), total_kind="exact", completeness={"status": "partial", "reason": "paginated_result"}
    )
    envelope["grouping"].update(kev_issue_total=int(counts["kev"]), total_basis="store_aggregate")
    envelope["warnings"] = [
        "Issue rows are paged from the first 50,000 occurrences; totals and severity counts are exact."
        if "Issue grouping stopped" in item
        else item
        for item in envelope["warnings"]
    ]
    if include_facets:
        envelope.setdefault("facets", {})["severity"] = {
            key: int(counts.get(key) or 0) for key in ("critical", "high", "medium", "low", "info", "unknown")
        }
        envelope.setdefault("facet_metadata", {})["severity_basis"] = "canonical issue groups"
