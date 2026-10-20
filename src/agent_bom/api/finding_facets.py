"""Finding facets."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from functools import partial
from typing import Any, NamedTuple

from agent_bom.api import compliance_hub_store
from agent_bom.api.finding_list_helpers import (
    _FACET_LITERAL_SEVERITY_BANDS,
    _FACET_PAYLOAD_SCOPE_KEYS,
    _FRESHNESS_BUCKETS,
    _freshness_bucket,
    _normalize_facet_severity,
)
from agent_bom.api.finding_reachability import iter_projected_rows
from agent_bom.api.finding_scope_filters import _row_matches_scope as _row_matches_scope
from agent_bom.api.finding_view_filters import _finding_triage_state as _finding_triage_state
from agent_bom.core.reachability import reachability_bucket
from agent_bom.finding_scope import FINDING_CLASSES, SECURITY_DOMAINS, finding_class_for_row, lenses_for_row

_FACET_SCAN_BUDGET = 50_000


_FACET_DEADLINE_SECONDS = 1.5


def _facet_severity_histogram(
    tenant_id: str,
    *,
    severity: str | None,
    scan_id: str | None,
    since: str | None,
    scope: Mapping[str, str],
    status: str,
) -> dict[str, int] | None:
    """Serve the self-excluding severity histogram from the store's aggregate.

    Every other facet dimension is gated on ``severity_matches``, so a
    ``?severity=`` request only needs severity-matching rows resident — except
    this histogram, which by contract excludes its own filter and therefore
    needs every band. Answering it with the store's indexed ``GROUP BY`` (the
    same one the overview headline reconciles against) lets the caller push
    ``severity`` into the store query and stop walking the non-matching
    remainder in Python.

    Returns ``None`` when the request is not expressible as that aggregate — no
    active severity filter (the walk is already minimal), a payload-side scope
    filter, a ``scan_id`` the aggregate does not carry, or a store without the
    capability — in which case the caller keeps the unfiltered walk unchanged.
    """
    if severity is None or scan_id is not None:
        return None
    if severity.strip().lower() not in _FACET_LITERAL_SEVERITY_BANDS:
        return None
    if any(key in scope for key in _FACET_PAYLOAD_SCOPE_KEYS):
        return None

    from agent_bom.api.compliance_hub_store import get_compliance_hub_store, status_matches
    from agent_bom.export.runner import iter_scan_spine_findings

    breakdown = getattr(get_compliance_hub_store(), "current_severity_breakdown", None)
    if not callable(breakdown):
        return None
    try:
        raw = breakdown(tenant_id, since=since, status=status)
    except TypeError:
        # A store whose aggregate cannot honour the active predicates would
        # silently answer a different question; keep the exact walk instead.
        return None

    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
    for band, value in dict(raw).items():
        counts[_normalize_facet_severity(band)] += int(value)

    # The aggregate covers the hub's current state only. The read path also
    # unions the resident scan spine, so fold its (bounded, in-memory) rows in
    # under the same predicates or the histogram would undercount a scan estate.
    for row in iter_scan_spine_findings(
        tenant_id,
        severity=None,
        since=since,
        scan_id=scan_id,
        scope=scope,
        status="all",
    ):
        if status_matches(row, status):
            counts[_normalize_facet_severity(row.get("severity"))] += 1
    return counts


def _finding_facets(
    tenant_id: str,
    *,
    severity: str | None,
    scan_id: str | None,
    since: str | None,
    scope: Mapping[str, str],
    status: str,
) -> tuple[dict[str, dict[str, int]], int]:
    facets, total, _metadata = _finding_facets_bounded(
        tenant_id,
        severity=severity,
        scan_id=scan_id,
        since=since,
        scope=scope,
        status=status,
    )
    return facets, total


_FACET_SEVERITY_BANDS = ("critical", "high", "medium", "low", "info", "unknown")


_TRIAGE_DISPOSITIONS = frozenset({"affected", "not_affected", "under_investigation"})


class _FacetScopes(NamedTuple):
    """Self-excluding scope variants: each dimension ignores its own filter."""

    full: dict[str, str]
    finding_class: dict[str, str]
    domain: dict[str, str]
    base: dict[str, str]

    @classmethod
    def from_scope(cls, scope: Mapping[str, str]) -> _FacetScopes:
        full = dict(scope)
        class_scope = {key: value for key, value in full.items() if key != "finding_class"}
        domain_scope = {key: value for key, value in full.items() if key != "domain"}
        base = {key: value for key, value in full.items() if key not in ("finding_class", "domain")}
        return cls(full=full, finding_class=class_scope, domain=domain_scope, base=base)


def _facet_graph_store() -> Any:
    from agent_bom.api.stores import _get_graph_store

    return _get_graph_store()


def _facet_reachability_bucket(row: Mapping[str, Any]) -> str:
    return reachability_bucket(row)


def _facet_exploit_bucket(row: Mapping[str, Any]) -> str:
    is_kev = row.get("is_kev") is True
    epss = row.get("epss_score")
    has_epss = isinstance(epss, (int, float)) and not isinstance(epss, bool)
    if is_kev:
        return "kev_and_epss" if has_epss else "kev_only"
    return "epss_only" if has_epss else "unavailable"


def _facet_has_fix(row: Mapping[str, Any]) -> bool:
    versions = row.get("remediation_versions")
    has_remediation_version = isinstance(versions, (list, tuple)) and any(str(value).strip() for value in versions)
    return bool(str(row.get("fixed_version") or "").strip()) or has_remediation_version


class _FacetCounts:
    """Mutable counters for one bounded facet walk."""

    def __init__(self) -> None:
        self.finding_class: dict[str, int] = {key: 0 for key in FINDING_CLASSES}
        self.severity: dict[str, int] = {key: 0 for key in _FACET_SEVERITY_BANDS}
        self.status: dict[str, int] = {key: 0 for key in ("open", "resolved")}
        self.domain: dict[str, int] = {key: 0 for key in SECURITY_DOMAINS}
        self.freshness: dict[str, int] = {key: 0 for key in _FRESHNESS_BUCKETS}
        self.reachability = {key: 0 for key in ("reachable", "unreachable", "unassessed")}
        self.exploit_intelligence = {key: 0 for key in ("kev_and_epss", "kev_only", "epss_only", "unavailable")}
        self.fixability = {key: 0 for key in ("fix_available", "no_fix_available")}
        self.ownership = {key: 0 for key in ("owned", "unowned")}
        self.disposition = {key: 0 for key in ("affected", "not_affected", "under_investigation", "untriaged")}
        self.total = 0

    def add_in_scope_row(self, row: dict[str, Any], triage_index: Any) -> None:
        """Count a row that matches every active filter."""
        self.total += 1
        self.freshness[_freshness_bucket(row)] += 1
        self.reachability[_facet_reachability_bucket(row)] += 1
        self.exploit_intelligence[_facet_exploit_bucket(row)] += 1
        self.fixability["fix_available" if _facet_has_fix(row) else "no_fix_available"] += 1
        triage_state = _finding_triage_state(row, triage_index)
        owner = str(row.get("owner") or "").strip() or str((triage_state or {}).get("assignee") or "").strip()
        self.ownership["owned" if owner else "unowned"] += 1
        decision = str((triage_state or {}).get("decision") or "").strip()
        self.disposition[decision if decision in _TRIAGE_DISPOSITIONS else "untriaged"] += 1

    def as_dict(self, pushed_severity: dict[str, int] | None) -> dict[str, dict[str, int]]:
        return {
            "finding_class": self.finding_class,
            "severity": pushed_severity if pushed_severity is not None else self.severity,
            "status": self.status,
            "domain": self.domain,
            "freshness": self.freshness,
            "reachability": self.reachability,
            "exploit_intelligence": self.exploit_intelligence,
            "fixability": self.fixability,
            "ownership": self.ownership,
            "disposition": self.disposition,
        }


def _count_facet_row(
    row: dict[str, Any],
    counts: _FacetCounts,
    *,
    severity: str | None,
    status: str,
    scopes: _FacetScopes,
    count_severity: bool,
    triage_index: Any,
) -> None:
    """Test one resident row against every dimension's self-excluding predicate."""
    finding_class = finding_class_for_row(row)
    row_severity = _normalize_facet_severity(row.get("severity"))
    # Re-checked in Python even when the predicate was pushed down, so a store
    # that ignores the kwarg degrades to slow, never to wrong.
    severity_matches = severity is None or row_severity == severity.lower()
    status_ok = compliance_hub_store.status_matches(row, status)
    full_scope_ok = _row_matches_scope(row, scopes.full)
    if severity_matches and status_ok and _row_matches_scope(row, scopes.finding_class):
        counts.finding_class[finding_class] += 1
    if count_severity and status_ok and full_scope_ok:
        # Only on the unfiltered walk: once ``severity`` is a store-side
        # predicate this stream no longer carries the other bands.
        counts.severity[row_severity] += 1
    if severity_matches and full_scope_ok:
        counts.status["resolved" if str(row.get("status") or "").strip().lower() == "resolved" else "open"] += 1
    if severity_matches and status_ok and _row_matches_scope(row, scopes.domain):
        for value in lenses_for_row(row):
            if value in counts.domain:
                counts.domain[value] += 1
    if severity_matches and status_ok and full_scope_ok:
        counts.add_in_scope_row(row, triage_index)


def _walk_facet_rows(
    rows: Iterable[dict[str, Any]],
    count_row: Callable[[dict[str, Any]], None],
    *,
    scan_budget: int,
    deadline_seconds: float,
) -> tuple[int, bool, str]:
    """Count rows until the row budget or the processing deadline is reached."""
    scanned_rows = 0
    deadline: float | None = None
    for row in rows:
        if scanned_rows >= scan_budget:
            return scanned_rows, True, "scan_budget"
        if deadline is None:
            # Bound facet processing, not the iterator's time-to-first-row: a
            # slow cursor setup must not turn a non-empty tenant into zero counts.
            deadline = time.monotonic() + max(0.001, deadline_seconds)
        elif time.monotonic() >= deadline:
            return scanned_rows, True, "deadline"
        scanned_rows += 1
        count_row(row)
    return scanned_rows, False, ""


def _facet_completeness(
    *, truncated: bool, reason: str, scanned_rows: int, scan_budget: int, deadline_seconds: float, total_exact: bool, severity_exact: bool
) -> dict[str, Any]:
    # Walk-derived dimensions stay lower bounds after a truncated walk; say per
    # dimension which is which so severity can be exact while others are not.
    walk_state = "bounded" if truncated else "exact"
    dimensions = {
        name: walk_state
        for name in ("finding_class", "severity", "status", "domain", "freshness", "reachability")
        + ("exploit_intelligence", "fixability", "ownership", "disposition")
    }
    dimensions["severity"] = "exact" if severity_exact else "bounded"
    return {
        "status": "partial" if truncated else "complete",
        "reason": reason,
        "scanned_rows": scanned_rows,
        "scan_budget": scan_budget,
        "deadline_ms": int(deadline_seconds * 1000),
        "total_exact": total_exact,
        "dimensions": dimensions,
    }


def _finding_facets_bounded(
    tenant_id: str,
    *,
    severity: str | None,
    scan_id: str | None,
    since: str | None,
    scope: Mapping[str, str],
    status: str,
    scan_budget: int | None = None,
    deadline_seconds: float | None = None,
) -> tuple[dict[str, dict[str, int]], int, dict[str, Any]]:
    """Compute self-excluding facets in one bounded canonical-stream pass.

    A row is tested against every dimension's self-excluding predicate while it
    is resident, avoiding four full tenant walks. When the row/deadline budget
    is reached the counts remain useful lower-bound evidence and are explicitly
    marked approximate by the caller.

    The budgets resolve from the module constants at call time so a test can
    reproduce truncation by lowering them instead of seeding 50k rows.
    """
    scan_budget = _FACET_SCAN_BUDGET if scan_budget is None else scan_budget
    deadline_seconds = _FACET_DEADLINE_SECONDS if deadline_seconds is None else deadline_seconds

    from agent_bom.api.routes.enterprise import build_tenant_triage_state_index
    from agent_bom.export.runner import iter_current_findings

    counts = _FacetCounts()
    triage_index = build_tenant_triage_state_index(tenant_id)
    scopes = _FacetScopes.from_scope(scope)
    # Severity is the only dimension that excludes its own filter; when the
    # store can answer it directly, ``severity`` becomes a store-side predicate
    # and the walk stops paying for non-matching rows.
    pushed = _facet_severity_histogram(tenant_id, severity=severity, scan_id=scan_id, since=since, scope=scopes.full, status=status)
    rows = iter_current_findings(
        tenant_id,
        severity=severity if pushed is not None else None,
        since=since,
        scan_id=scan_id,
        scope=scopes.base,
        status="all",
        sanitize=False,
    )
    rows = iter_projected_rows(rows, graph_store=_facet_graph_store(), tenant_id=tenant_id, scan_id=scan_id)
    count_row = partial(
        _count_facet_row,
        counts=counts,
        severity=severity,
        status=status,
        scopes=scopes,
        count_severity=pushed is None,
        triage_index=triage_index,
    )
    scanned_rows, truncated, reason = _walk_facet_rows(rows, count_row, scan_budget=scan_budget, deadline_seconds=deadline_seconds)
    # ``total`` and the severity histogram must answer the same question on the
    # same basis. Under pushdown the histogram is the store's unbounded aggregate
    # with identical predicates, so its count for the filtered band is the exact
    # total even when the row-budgeted walk was truncated.
    total, total_exact = counts.total, not truncated
    if truncated and pushed is not None and severity is not None:
        total = pushed.get(_normalize_facet_severity(severity), total)
        total_exact = True
    completeness = _facet_completeness(
        truncated=truncated,
        reason=reason,
        scanned_rows=scanned_rows,
        scan_budget=scan_budget,
        deadline_seconds=deadline_seconds,
        total_exact=total_exact,
        severity_exact=pushed is not None or not truncated,
    )
    return counts.as_dict(pushed), total, completeness
