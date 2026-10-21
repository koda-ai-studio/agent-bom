"""Canonical scan-result to posture-trend persistence boundary."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from agent_bom.api.exec_posture import tenant_headline_posture, tenant_issue_counts
from agent_bom.baseline import TrendPoint
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)
_SEVERITIES = ("critical", "high", "medium", "low")
_ISSUE_KEYS = ("critical", "high", "medium", "low", "unrated", "total", "kev", "approximate", "basis")


def _vulnerability_severities(result: Mapping[str, Any]) -> list[str]:
    severities: list[str] = []
    packages = result.get("packages")
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, Mapping):
                continue
            vulnerabilities = package.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if isinstance(vulnerability, Mapping):
                    severities.append(str(vulnerability.get("severity") or "unknown").strip().lower())
    if severities:
        return severities
    blast_radius = result.get("blast_radius") or result.get("blast_radii")
    if isinstance(blast_radius, list):
        for finding in blast_radius:
            if isinstance(finding, Mapping):
                severities.append(str(finding.get("severity") or "unknown").strip().lower())
    return severities


def trend_point_from_scan_result(
    result: Mapping[str, Any],
    *,
    tenant_id: str,
    scan_id: str | None = None,
    completed_at: str | None = None,
    scope_id: str | None = None,
    headline: Mapping[str, Any] | None = None,
    issue_counts: Mapping[str, Any] | None = None,
) -> TrendPoint | None:
    """Build one honest, retry-safe trend point from canonical scan JSON.

    ``headline`` is the tenant posture the overview serves after this scan was
    persisted; when given, the point records that grade and score so the trend
    and the posture endpoints are one derivation. ``issue_counts`` are the open
    issue groups ``/v1/posture/counts`` serves at that moment; only that basis
    is recorded, so a plotted point is the headline's own unit. The scan must
    still carry a gradable scorecard: an ungradable scan never adds a point.
    """
    from agent_bom.api.trend_comparison import comparison_metadata

    scorecard = result.get("posture_scorecard")
    if not isinstance(scorecard, Mapping) or bool(scorecard.get("no_data")):
        return None
    grade = str(scorecard.get("grade") or "").strip().upper()
    if not grade or grade == "N/A":
        return None
    try:
        score = float(scorecard["score"])
    except (KeyError, TypeError, ValueError):
        return None
    if headline is not None:
        headline_grade = str(headline.get("grade") or "").strip().upper()
        headline_score = score
        try:
            headline_score = float(headline["score"])
        except (KeyError, TypeError, ValueError):
            headline_grade = ""
        if headline_grade and headline_grade != "N/A":
            grade, score = headline_grade, headline_score
    resolved_scan_id = str(scan_id or result.get("scan_id") or "").strip()
    if not resolved_scan_id:
        return None
    timestamp = str(completed_at or result.get("generated_at") or "").strip()
    if not timestamp:
        return None
    severities = _vulnerability_severities(result)
    counts = {severity: severities.count(severity) for severity in _SEVERITIES}
    metadata = comparison_metadata(result, scope_id, timestamp)
    if issue_counts is not None and issue_counts.get("basis") == "issue_groups":
        metadata["issue_counts"] = {key: issue_counts.get(key) for key in _ISSUE_KEYS}
    return TrendPoint(
        timestamp=timestamp,
        total_vulns=len(severities),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        posture_score=score,
        posture_grade=grade,
        tenant_id=str(tenant_id or "default"),
        scan_id=resolved_scan_id,
        comparison_metadata=metadata,
    )


def record_scan_trend_best_effort(
    result: Mapping[str, Any],
    *,
    tenant_id: str,
    scan_id: str | None = None,
    completed_at: str | None = None,
    scope_id: str | None = None,
    headline_posture: bool = False,
) -> bool:
    """Persist one trend point; return whether a gradable point was recorded.

    ``headline_posture`` is for callers that have already persisted the job:
    the point then records the tenant's current headline posture and issue counts.
    """
    tenant = str(tenant_id or "default")
    headline = tenant_headline_posture(tenant) if headline_posture else None
    issue_counts = tenant_issue_counts(tenant) if headline_posture else None
    point = trend_point_from_scan_result(
        result,
        tenant_id=tenant_id,
        scan_id=scan_id,
        completed_at=completed_at,
        scope_id=scope_id,
        headline=headline,
        issue_counts=issue_counts,
    )
    if point is None:
        return False
    try:
        from agent_bom.api.stores import _get_trend_store
        from agent_bom.api.trend_comparison import retain_open_interval

        store = _get_trend_store()
        retain_open_interval(point, store.get_history(limit=365, tenant_id=point.tenant_id))
        store.record(point)
    except Exception as exc:  # noqa: BLE001 - trend history must not fail a completed scan
        _logger.warning("Posture trend persistence skipped: %s", sanitize_text(sanitize_error(exc, generic=True)))
        return False
    return True
