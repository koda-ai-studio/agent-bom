"""Snapshot-consistent hub aggregates for Overview."""

from __future__ import annotations

import logging
import time
from typing import Any, NoReturn

from fastapi import HTTPException, Request

from agent_bom.api.overview_rollup import (
    _COVERAGE_DOMAINS,
    _COVERAGE_LABELS,
    _current_open_scan_findings,
    _empty_severity,
    _finding_top_risk,
    _fold_current_coverage,
    _tenant_id,
)
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger("agent_bom.api.routes.overview")


def _raise_hub_overview_unavailable() -> NoReturn:
    raise HTTPException(
        status_code=503,
        detail="Overview evidence is temporarily unavailable; retry the request.",
        headers={"Retry-After": "1"},
    )


def _hub_severity_snapshot(
    request: Request,
    *,
    revision: int | None = None,
    strict: bool = False,
) -> dict[str, int]:
    """Per-severity counts of hub-ingested findings (POST /v1/findings/bulk).

    Reads the CURRENT-STATE table (``hub_findings_current``) with the SAME
    origin + default read-window predicates that ``/v1/findings`` counts on, via
    the store's indexed ``current_severity_breakdown`` (a GROUP BY, no payload
    hydration). This is the exec-read honesty fix (#3961): the headline used to
    read the append-only ledger (``severity_breakdown`` — all-origin, unbounded,
    keeping resolved/aged rows forever), so it could exceed and contradict the
    drill-down. Deriving from current-state within the window makes the headline
    reconcile EXACTLY with a ``/v1/findings`` click-through.

    Tenant scope is owned by the request; the store method is tenant-keyed.
    Degrades to zeros if the hub store is unavailable so the overview never fails
    closed on an optional dependency.
    """
    empty = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    tenant_id = _tenant_id(request)
    # Memoise the O(rows) severity GROUP BY per tenant. This snapshot feeds BOTH
    # the cache fingerprint and the composed payload, so without this it ran the
    # full scan on every /v1/overview request (~360ms at 1M). The cache is
    # invalidated on every hub mutation (ingest / clear), so a hit is exact
    # and reconciles with the findings API by construction (wave-2 residual #3).
    from agent_bom.api import hub_overview_cache

    cached = hub_overview_cache.get_cached_severity(tenant_id, revision=revision) if revision is not None else None
    if cached is not None:
        return cached
    try:
        from agent_bom.api import time_window
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        store = get_compliance_hub_store()
        current_breakdown = getattr(store, "current_severity_breakdown", None)
        if callable(current_breakdown):
            # Same default read-window ``/v1/findings`` applies (window_days
            # unset ⇒ server default ≈90d), the same ``bulk_ingest`` origin scope,
            # AND the same default OPEN lifecycle basis — resolved findings must
            # not inflate the exec headline. So the headline == the drill-down for
            # the same window + live posture (P1: lifecycle-aware exec read).
            since = time_window.window_since_iso(time_window.normalize_window_days(None))
            counts = current_breakdown(tenant_id, origin="bulk_ingest", since=since, status="open") or {}
        else:
            if strict:
                _raise_hub_overview_unavailable()
            breakdown = getattr(store, "severity_breakdown", None)
            if not callable(breakdown):
                return empty
            counts = breakdown(tenant_id) or {}
    except Exception:  # pragma: no cover - hub store optional
        _logger.debug("hub severity snapshot failed", exc_info=False)
        if strict:
            _raise_hub_overview_unavailable()
        return empty
    for key, value in counts.items():
        empty[str(key).lower()] = empty.get(str(key).lower(), 0) + int(value or 0)
    if revision is not None:
        hub_overview_cache.set_cached_severity(tenant_id, empty, revision=revision)
    return empty


def _hub_kev_snapshot(
    request: Request,
    *,
    revision: int | None = None,
    strict: bool = False,
) -> int:
    """Count of hub-ingested findings flagged CISA-KEV (same window/origin as the
    severity snapshot).

    The exec KEV headline used to source KEV from the scan-lane rollup only, so a
    connector/bulk-ingested KEV finding showed in the /v1/findings drill but never
    moved the headline. This reads the hub current-state via the store's
    ``current_kev_count`` (the same spine the drill hydrates KEV from) so the two
    reconcile. Memoised per tenant with the severity snapshot's invalidation
    contract; degrades to 0 if the hub store is unavailable.
    """
    from agent_bom.api import hub_overview_cache

    tenant_id = _tenant_id(request)
    cached = hub_overview_cache.get_cached_kev(tenant_id, revision=revision) if revision is not None else None
    if cached is not None:
        return cached
    try:
        from agent_bom.api import time_window
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        store = get_compliance_hub_store()
        counter = getattr(store, "current_kev_count", None)
        if not callable(counter):
            if strict:
                _raise_hub_overview_unavailable()
            return 0
        since = time_window.window_since_iso(time_window.normalize_window_days(None))
        count = int(counter(tenant_id, origin="bulk_ingest", since=since, status="open") or 0)
    except Exception:  # pragma: no cover - hub store optional
        _logger.debug("hub kev snapshot failed", exc_info=False)
        if strict:
            _raise_hub_overview_unavailable()
        return 0
    if revision is not None:
        hub_overview_cache.set_cached_kev(tenant_id, count, revision=revision)
    return count


def _hub_failing_frameworks_snapshot(
    request: Request,
    *,
    revision: int | None = None,
    strict: bool = False,
) -> set[str]:
    """Distinct framework mappings on live high/critical hub findings.

    Uses the same tenant, bulk-ingest origin, open lifecycle, and default window
    as the hub severity headline. SQL backends aggregate their denormalized CSV
    in-database, so Overview never hydrates the tenant ledger.
    """
    from agent_bom.api import hub_overview_cache, time_window
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    tenant_id = _tenant_id(request)
    cached = hub_overview_cache.get_cached_failing_frameworks(tenant_id, revision=revision) if revision is not None else None
    if cached is not None:
        return set(cached)
    try:
        counter = getattr(get_compliance_hub_store(), "current_failing_framework_slug_counts", None)
        if not callable(counter):
            if strict:
                _raise_hub_overview_unavailable()
            return set()
        since = time_window.window_since_iso(time_window.normalize_window_days(None))
        counts = counter(tenant_id, origin="bulk_ingest", since=since, status="open") or {}
    except Exception as exc:  # pragma: no cover - hub store optional
        _logger.debug(
            "hub framework snapshot failed: %s",
            sanitize_text(sanitize_error(exc, generic=True)),
        )
        if strict:
            _raise_hub_overview_unavailable()
        return set()
    from agent_bom.compliance_coverage import normalize_framework_slug, scored_framework_slugs

    scored_slugs = scored_framework_slugs()
    normalized: dict[str, int] = {}
    for slug, count in counts.items():
        canonical = normalize_framework_slug(str(slug)) if slug else ""
        if canonical in scored_slugs and int(count or 0) > 0:
            normalized[canonical] = normalized.get(canonical, 0) + int(count or 0)
    if revision is not None:
        hub_overview_cache.set_cached_failing_frameworks(tenant_id, normalized, revision=revision)
    return set(normalized)


_HUB_TOP_RISK_LIMIT = 10


def _hub_top_risks(
    request: Request,
    *,
    limit: int = _HUB_TOP_RISK_LIMIT,
    strict: bool = False,
) -> list[dict[str, Any]]:
    """Top hub-ingested findings for the exec top-risk strip (P0 #1).

    ``_estate_rollup`` walks scan jobs only, so a connector/bulk-ingested estate
    rendered an empty top-risk strip even with a million open findings that DO
    move the grade + headline (via ``_hub_severity_snapshot``). This folds the
    hub finding spine into the strip. It reads a single bounded CURRENT-STATE
    page with the same bulk-ingest origin, open lifecycle, and default window as
    the headline. The materialised ``severity_rank`` ordering is index-backed on
    SQL backends, so it stays sub-linear at million-row scale and never revives
    resolved/aged ledger history in a live executive surface.

    Sorting by severity, NOT ``effective_reach``: the bulk/connector payload this
    targets carries only severity + CVSS, so ``compute_effective_reach_score`` is
    0.0 for every row — a reach-ordered page ties them all at 0.0 and degenerates
    to ingest/rowid order, so the single worst finding (a lone critical behind
    thousands of mediums) fell off the strip entirely. Severity-first ordering
    guarantees the worst band is surfaced regardless of ingest order; the
    per-entry ``_row_risk_score`` blend then refines within-band by CVSS.
    Degrades to an empty list if the hub store is unavailable so the overview
    never fails closed on an optional dependency.
    """
    if limit <= 0:
        return []
    try:
        from agent_bom.api import time_window
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        store = get_compliance_hub_store()
        list_current = getattr(store, "list_current_page", None)
        if not callable(list_current):
            if strict:
                _raise_hub_overview_unavailable()
            return []
        since = time_window.window_since_iso(time_window.normalize_window_days(None))
        page = list_current(
            _tenant_id(request),
            limit=limit,
            sort="severity",
            origin="bulk_ingest",
            since=since,
            status="open",
            include_total=False,
        )
    except Exception:  # pragma: no cover - hub store optional
        _logger.debug("hub top risks failed", exc_info=False)
        if strict:
            _raise_hub_overview_unavailable()
        return []
    rows = page[0] if isinstance(page, tuple) else page
    return [_finding_top_risk(row) for row in rows or [] if isinstance(row, dict)]


def _hub_coverage_snapshot(
    request: Request,
    hub_store: Any,
    revision: int | None,
) -> tuple[dict[str, dict[str, int]], str]:
    """One bounded keyset pass for all lanes, cached at the durable revision.

    Exact persisted domain aggregates are not available. Row/deadline exhaustion
    retains known counts and marks every lane partial, including zero-count lanes.
    """
    from agent_bom.api import hub_overview_cache, time_window
    from agent_bom.api.compliance_hub_store import scope_filter_deadline_seconds, scope_filter_scan_budget

    tenant_id = _tenant_id(request)
    if revision is not None:
        cached = hub_overview_cache.get_cached_coverage(tenant_id, revision)
        if cached is not None:
            return cached
    from agent_bom.api.overview_cve_counts import empty_cve_counts

    lanes = {domain: _empty_severity() for domain in _COVERAGE_DOMAINS}
    lanes["_cves"] = empty_cve_counts()
    pager = getattr(hub_store, "list_current_page", None)
    if not callable(pager):
        return lanes, "unavailable"
    remaining = scope_filter_scan_budget()
    deadline = time.monotonic() + scope_filter_deadline_seconds()
    cursor: str | None = None
    status = "partial"
    since = time_window.window_since_iso(time_window.normalize_window_days(None))
    try:
        while remaining > 0 and time.monotonic() < deadline:
            page, _total, next_cursor = pager(
                tenant_id,
                limit=min(200, remaining),
                sort="ordinal",
                origin="bulk_ingest",
                status="open",
                since=since,
                include_total=False,
                cursor=cursor,
            )
            for row in page:
                _fold_current_coverage(lanes, row)
            remaining -= len(page)
            if not next_cursor:
                status = "complete"
                break
            if next_cursor == cursor or not page:
                break
            cursor = next_cursor
    except Exception:
        # Counts accumulated before a failed read remain lower bounds. Do not
        # leak backend errors or describe the unread portion as an empty estate.
        status = "unavailable"
        _logger.debug("hub discipline coverage read unavailable", exc_info=False)
    if revision is not None and status != "unavailable":
        hub_overview_cache.set_cached_coverage(tenant_id, revision, lanes, status)
    return lanes, status


def _current_coverage(
    jobs: list[Any],
    hub_coverage: tuple[dict[str, dict[str, int]], str],
    *,
    cve_counts: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    hub_lanes, status = hub_coverage
    lanes = {domain: dict(hub_lanes[domain]) for domain in _COVERAGE_DOMAINS}
    if cve_counts is not None:
        lanes["_cves"] = cve_counts
    for row in _current_open_scan_findings(jobs):
        _fold_current_coverage(lanes, row)
    return [
        {
            "domain": domain,
            "label": _COVERAGE_LABELS[domain],
            "href": f"/findings?domain={domain}",
            "count": sum(lanes[domain].values()),
            "severity": lanes[domain],
            "evidence_status": status,
            "count_exact": status == "complete",
        }
        for domain in _COVERAGE_DOMAINS
    ]
