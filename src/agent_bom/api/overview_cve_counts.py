"""Vuln / SCA occurrence counts shared by current scan and pushed-evidence folds."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from agent_bom.core.severity import empty_severity_histogram, severity_display_bucket
from agent_bom.finding_scope import row_matches_scope


def empty_cve_counts() -> dict[str, int]:
    return {**empty_severity_histogram(), "kev": 0}


# The Vuln / SCA card links to exactly this findings query, and counts rows with
# the same predicate the findings API applies to it, so the card always equals
# the page it opens.
VULN_CARD_FILTERS: dict[str, str] = {"finding_class": "vulnerability", "domain": "vuln"}
VULN_CARD_HREF = "/findings?issue=vulnerability&domain=vuln"


def add_cve_finding(counts: dict[str, int], row: Mapping[str, Any]) -> None:
    """Fold an already current, open occurrence that the Vuln / SCA drill would list.

    Vulnerability-class rows in the vuln domain: CVE and GHSA advisories,
    malicious packages, and other vulnerability-class rows that name a CVE.
    Configuration, secret, runtime-threat and cloud-posture rows stay out.
    Lifecycle, tenant, time-window and
    occurrence deduplication belong to the current-evidence readers that feed
    this fold.
    """
    if not row_matches_scope(dict(row), VULN_CARD_FILTERS):
        return
    counts[severity_display_bucket(str(row.get("severity") or ""))] += 1
    counts["kev"] += int(bool(row.get("is_kev") or row.get("cisa_kev")))


def compose_cve_domain(
    scan: Mapping[str, int],
    hub: Mapping[str, int],
    *,
    scan_complete: bool,
    hub_status: str,
    packages: int,
    graph_href: Callable[[dict[str, int]], str],
) -> dict[str, Any]:
    """Expose occurrence counts and lower-bound metadata without inventing zeroes."""
    severity = {band: scan.get(band, 0) + hub.get(band, 0) for band in empty_severity_histogram()}
    metric = sum(severity.values())
    exact = scan_complete and hub_status == "complete"
    evidence_status = hub_status if hub_status != "complete" else ("complete" if exact else "partial")
    status = "critical" if severity["critical"] else ("warn" if severity["high"] else "ok")
    if not metric:
        status = "idle" if exact else "unknown"
    return {
        "label": "Vuln / SCA",
        "href": VULN_CARD_HREF,
        "graph_href": graph_href(severity),
        "metric": metric,
        "metric_label": "open vulnerability findings",
        "count_exact": exact,
        "evidence_status": evidence_status,
        "status": status,
        "detail": {
            "critical": severity["critical"],
            "high": severity["high"],
            "kev": scan.get("kev", 0) + hub.get("kev", 0),
            "packages": packages,
            "severity": severity,
        },
    }
