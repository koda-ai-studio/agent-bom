"""Db sync parsing helpers."""

from __future__ import annotations

import re
from typing import Any, Callable, Optional

from agent_bom.core.versions.osv import before_limit, is_release_range, range_limits, range_windows
from agent_bom.db.lookup import _comparator_ecosystem
from agent_bom.db.osv_metadata import osv_relationship_metadata
from agent_bom.models import Severity
from agent_bom.scanners.risk import osv_severity_basis

# OSV severity mapping (CVSS v3 ranges)
_CVSS_SEVERITY = {
    (9.0, 10.0): "critical",
    (7.0, 8.9): "high",
    (4.0, 6.9): "medium",
    (0.1, 3.9): "low",
}


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score == 0.0:
        return "none"
    for (lo, hi), sev in _CVSS_SEVERITY.items():
        if lo <= score <= hi:
            return sev
    return "unknown"


# ---------------------------------------------------------------------------
# OSV ingestion
# ---------------------------------------------------------------------------


def _is_commit_bound(bound: str | None) -> bool:
    """Whether an advisory range bound is a git commit rather than a version.

    Shares ``version_utils``' heuristic so the sync and match paths agree on
    what counts as unorderable. ``"0"`` is OSV's "from the beginning" sentinel.
    """
    if not bound or bound == "0":
        return False
    from agent_bom.version_utils import _looks_like_commit_sha

    return _looks_like_commit_sha(bound)


def _window_coverage(windows: list[dict]) -> Callable[[str], bool]:
    """Return a predicate: does a stored window definitively match a version?

    Mirrors ``lookup._version_match_state(...) == "affected"`` for windows that
    already passed the commit-bound filter, so ingest never drops a pin the
    matcher could not reproduce; an ambiguous comparison keeps the pin. Bounds
    are resolved once per block because a feed can enumerate thousands of
    releases against the same window.
    """
    if not windows:
        return lambda _version: False

    from agent_bom.version_utils import compare_version_order, normalize_introduced

    comparator = _comparator_ecosystem(windows[0]["ecosystem"])
    bounds = [
        (normalize_introduced(w["introduced"]), w["fixed"] or None, w["last_affected"] or None, w.get("limit_version", "")) for w in windows
    ]

    def covered(version: str) -> bool:
        for intro, fix, last, limit in bounds:
            if before_limit(version, limit, comparator) is not True:
                continue
            if intro:
                cmp = compare_version_order(version, intro, comparator)
                if cmp is None or cmp < 0:
                    continue
            if fix:
                cmp = compare_version_order(version, fix, comparator)
                if cmp is None or cmp >= 0:
                    continue
            if last:
                cmp = compare_version_order(version, last, comparator)
                if cmp is None or cmp > 0:
                    continue
            return True
        return False

    return covered


def _parse_osv_entry(data: dict) -> Optional[tuple[dict, list[dict]]]:
    """Parse one OSV JSON entry into (vuln_row, affected_rows).

    Returns None if the entry is missing required fields or is a withdrawn advisory.
    """
    vuln_id = data.get("id", "")
    if not vuln_id:
        return None
    if data.get("withdrawn"):
        return None  # skip withdrawn advisories

    summary = data.get("summary") or data.get("details", "")[:200]
    published = data.get("published", "")
    modified = data.get("modified", "")

    # One severity basis shared with the online OSV scanner (see
    # ``osv_severity_basis``) so `--offline` and online gates agree. The
    # advisory-namespace fallback is applied at read time, never persisted.
    basis = osv_severity_basis(data, advisory_id_fallback=False)
    db_specific = data.get("database_specific", {})
    cvss_score: Optional[float] = basis.cvss_score
    cvss_vector: Optional[str] = basis.cvss_vector
    severity = basis.severity.value if basis.severity != Severity.UNKNOWN else "unknown"

    fixed_version, affected_rows = _osv_affected_rows(data, vuln_id)

    vuln_row = {
        "id": vuln_id,
        "summary": summary[:500],
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "fixed_version": fixed_version,
        **osv_relationship_metadata(data, db_specific),
        "published": published,
        "modified": modified,
        "source": "osv",
    }
    return vuln_row, affected_rows


def _parse_alpine_secfix_tokens(value: object) -> list[str]:
    """Extract vulnerability identifiers from one Alpine secdb secfix value."""
    if not isinstance(value, str):
        return []
    return re.findall(r"(?:CVE-\d{4}-\d+|ALPINE-\d+|XSA-\d+)", value)


# ---------------------------------------------------------------------------
# Debian Security Tracker ingestion
# ---------------------------------------------------------------------------


def _parse_debian_tracker_release_entry(entry: object) -> Optional[tuple[str, str]]:
    """Map one tracker release block to ``(status, fixed_version)`` or ``None``.

    Returns:
        ``("resolved", "<fix>")`` — the release ships a fix; ``<fix>`` is the
            per-release (backported) version where the CVE is fixed.
        ``("open", "")`` — the release is affected with no fix available. This is
            the tracker's no-dsa / ignored / won't-fix / end-of-life verdict;
            stored with an empty fix so the default OS-advisory suppression hides
            it (and ``AGENT_BOM_INCLUDE_UNFIXED=1`` restores it), exactly like
            other distro sources.
        ``None`` — ``undetermined`` / ``not-affected`` / unknown status carry no
            actionable verdict and are not stored (avoids false positives).
    """
    if not isinstance(entry, dict):
        return None
    status = str(entry.get("status") or "").strip().lower()
    if status == "resolved":
        fixed = str(entry.get("fixed_version") or "").strip()
        # "0" is the tracker sentinel for "this release was never affected".
        if not fixed or fixed == "0":
            return None
        return "resolved", fixed
    if status == "open":
        return "open", ""
    return None


# ---------------------------------------------------------------------------
# GHSA ingestion
# ---------------------------------------------------------------------------


def _parse_ghsa_version_range(version_range: Optional[str]) -> tuple[str, str]:
    """Parse a GHSA version range string into (introduced, fixed).

    GHSA uses strings like ``">= 1.0, < 2.0"`` or ``"< 3.5"`` or ``">= 0"``.
    Returns ``("", "")`` when the range cannot be parsed.
    """
    if not version_range:
        return "", ""
    introduced = ""
    fixed = ""
    for part in version_range.split(","):
        part = part.strip()
        if part.startswith(">="):
            introduced = part[2:].strip()
        elif part.startswith("<"):
            fixed = part[1:].strip()
    return introduced, fixed


def _extract_nvd_cve_fields(cve_data: dict[str, Any]) -> dict[str, Any]:
    """Extract CVSS/CWE/summary fields from one NVD CVE object."""
    metrics = cve_data.get("metrics") or {}
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: Optional[str] = None

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key) or []
        if not metric_list:
            continue
        cvss_data = metric_list[0].get("cvssData") or {}
        raw_score = cvss_data.get("baseScore")
        if raw_score is not None:
            try:
                cvss_score = float(raw_score)
            except (TypeError, ValueError):
                cvss_score = None
        cvss_vector = cvss_data.get("vectorString")
        raw_sev = (cvss_data.get("baseSeverity") or "").lower()
        if raw_sev in ("critical", "high", "medium", "low"):
            severity = raw_sev
        break

    nvd_cwes: list[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-") and cwe_val not in nvd_cwes:
                nvd_cwes.append(cwe_val)

    if not severity and cvss_score is not None:
        severity = _cvss_to_severity(cvss_score)

    descriptions = cve_data.get("descriptions") or []
    summary = ""
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            summary = str(desc["value"])[:500]
            break

    return {
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwe_ids": nvd_cwes,
        "summary": summary,
    }


def _cpe_version_bound(match: dict[str, Any], including_key: str, excluding_key: str) -> tuple[Optional[str], Optional[str]]:
    """Return (value, op) for one CPE version bound — 'including'/'excluding' or (None, None)."""
    inc = match.get(including_key)
    if inc:
        return str(inc), "including"
    exc = match.get(excluding_key)
    if exc:
        return str(exc), "excluding"
    return None, None


def _extract_nvd_cpe_matches(cve_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract vulnerable CPE applicability ranges from one NVD CVE object.

    NVD 2.0 nests applicability as ``configurations[].nodes[].cpeMatch[]``; each
    match carries a ``cpe:2.3:part:vendor:product:version:...`` criteria string
    plus optional version-range bounds. Only ``vulnerable`` matches are kept.
    """
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, Optional[str], Optional[str]]] = set()
    for config in cve_data.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = str(match.get("criteria") or "")
                parts = criteria.split(":")
                if not criteria.startswith("cpe:2.3:") or len(parts) < 6:
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                start, start_op = _cpe_version_bound(match, "versionStartIncluding", "versionStartExcluding")
                end, end_op = _cpe_version_bound(match, "versionEndIncluding", "versionEndExcluding")
                key = (criteria, start, end)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "criteria": criteria,
                        "vendor": vendor,
                        "product": product,
                        "version": version if version not in ("*", "-", "") else None,
                        "version_start": start,
                        "version_start_op": start_op,
                        "version_end": end,
                        "version_end_op": end_op,
                    }
                )
    return rows


def _osv_affected_rows(data: dict, vuln_id: str) -> tuple[str | None, list[dict]]:
    # Fixed version — take first fixed range across all affected entries
    fixed_version: Optional[str] = None
    affected_rows: list[dict] = []
    from agent_bom.os_advisory import normalize_redhat_ecosystem
    from agent_bom.package_utils import normalize_package_name

    for aff in data.get("affected", []):
        pkg = aff.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        pkg_name = pkg.get("name", "")
        if not ecosystem or not pkg_name:
            continue
        # Collapse repo/module-qualified Red Hat ecosystems (``…:8::baseos``,
        # ``…:10.0``) to a canonical per-major key so a scanned host — which
        # cannot know a package's originating repo — matches exactly.
        ecosystem = normalize_redhat_ecosystem(ecosystem)
        norm_name = normalize_package_name(pkg_name, ecosystem)
        range_rows: list[dict] = []
        for rng in aff.get("ranges", []):
            if not is_release_range(rng):
                continue
            # OSV encodes per-branch fixes as alternating introduced/fixed
            # events inside ONE range. Each pair is its own vulnerable window;
            # keeping only the last one hides every earlier branch.
            windows = range_windows(rng.get("events", []), _comparator_ecosystem(ecosystem))
            for _, fixed, _ in windows:
                if fixed_version is None and fixed and not _is_commit_bound(fixed):
                    fixed_version = fixed

            for limit_version in range_limits(rng.get("events", [])):
                for win_introduced, win_fixed, win_last_affected in windows:
                    # A commit SHA carries no order against a release version, so a
                    # window bounded by one can never be matched — storing it only
                    # adds a row that reads as real coverage. Worse, a commit window
                    # whose fix event is absent degenerates to "vulnerable through
                    # latest" and matches every version.
                    if any(_is_commit_bound(bound) for bound in (win_introduced, win_fixed, win_last_affected, limit_version)):
                        continue
                    range_rows.append(
                        {
                            "vuln_id": vuln_id,
                            "ecosystem": ecosystem.lower(),
                            "package_name": norm_name,
                            "introduced": win_introduced or "",
                            "fixed": win_fixed or "",
                            "last_affected": win_last_affected or "",
                            "limit_version": limit_version,
                        }
                    )

        # OSV defines the affected set as the union of versions and ranges. GIT
        # bounds cannot place a package release, and an ECOSYSTEM range may
        # describe only a later reintroduction window, so an enumerated release
        # the stored windows do not definitively cover is kept as an exact pin.
        # Releases a window already covers add nothing but rows: feeds list
        # every affected release, which multiplied the table ~30x.
        pinned: set[str] = set()
        covered = _window_coverage(range_rows)
        for version in aff.get("versions") or []:
            if not isinstance(version, str) or not version.strip():
                continue
            version = version.strip()
            if version in pinned or covered(version):
                continue
            pinned.add(version)
            affected_rows.append(
                {
                    "vuln_id": vuln_id,
                    "ecosystem": ecosystem.lower(),
                    "package_name": norm_name,
                    "introduced": version,
                    "fixed": "",
                    "last_affected": version,
                    "limit_version": "",
                }
            )
        affected_rows.extend(range_rows)

    return fixed_version, affected_rows
