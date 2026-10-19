"""Finding and scan summary projections for Overview."""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import urlencode

from fastapi import Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.core.severity import SEVERITY_DISPLAY_BUCKETS, SEVERITY_THRESHOLD_LABELS, UNRATED_SEVERITY_BUCKET, severity_display_bucket

_SEVERITY_KEYS = SEVERITY_THRESHOLD_LABELS


_UNRATED_KEY = UNRATED_SEVERITY_BUCKET


_ALL_SEVERITY_KEYS = SEVERITY_DISPLAY_BUCKETS


_COVERAGE_DOMAINS = ("cspm", "vuln", "aspm", "dspm", "aispm")


_COVERAGE_LABELS = {
    "cspm": "CSPM",
    "vuln": "Vuln mgmt",
    "aspm": "ASPM",
    "dspm": "DSPM",
    "aispm": "AISPM",
}


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _empty_severity() -> dict[str, int]:
    return {key: 0 for key in _ALL_SEVERITY_KEYS}


def _bucket(sev: str | None, severity: dict[str, int]) -> str:
    """Return the histogram bucket for ``sev`` — an exact match or ``unrated``.

    The single choke point shared by every rollup so a finding is counted in one
    and only one bucket and no unknown severity is silently dropped. Delegates
    to ``graph.severity`` so this module and every other severity strip in the
    product answer the question identically.
    """
    return severity_display_bucket(sev)


def _graph_drill_href(
    *,
    rollup: bool = True,
    severity: str | None = None,
    relationships: str | None = None,
    layers: str | None = None,
) -> str:
    """Build a /graph deep-link for overview domain tiles."""
    params: dict[str, str] = {}
    if rollup:
        params["rollup"] = "1"
    if severity:
        params["severity"] = severity
    if relationships:
        params["relationships"] = relationships
    if layers:
        params["layers"] = layers
    query = urlencode(params)
    return f"/graph?{query}" if query else "/graph"


def _cloud_graph_href(severity: dict[str, int]) -> str:
    if severity["critical"] > 0:
        return _graph_drill_href(severity="critical")
    if severity["high"] > 0:
        return _graph_drill_href(severity="high")
    return _graph_drill_href()


def _severity_from_summary(
    summary: dict[str, Any],
    finding_summary: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Rebuild severity histogram from compact scan ``summary`` metadata."""
    severity = _empty_severity()
    total = int(summary.get("total_vulnerabilities") or summary.get("total_findings") or 0)
    by_sev = (finding_summary or {}).get("by_severity") or {}
    if isinstance(by_sev, dict) and by_sev:
        for raw_key, raw_val in by_sev.items():
            severity[_bucket(str(raw_key), severity)] += int(raw_val or 0)
        counted = sum(severity.values())
        # Reconcile with the scalar total so no finding is lost to a severity
        # band the per-severity map omitted (info/unknown/vendor-specific).
        if total > counted:
            severity[_UNRATED_KEY] += total - counted
        return severity
    severity["critical"] = int(summary.get("critical_unified_findings") or summary.get("critical_findings") or 0)
    severity["high"] = int(summary.get("high_unified_findings") or 0)
    # The remainder are of unknown band (only critical/high are itemized in the
    # compact summary) — record them as ``unrated`` rather than fabricating a
    # ``medium`` count. This keeps ``sum(severity) == total``.
    remainder = max(0, total - severity["critical"] - severity["high"])
    if remainder:
        severity[_UNRATED_KEY] = remainder
    return severity


def _rollup_from_blast_radius(blast_radius: list[dict[str, Any]]) -> dict[str, Any]:
    severity = _empty_severity()
    kev = 0
    credential_exposed = 0
    seen_ids: set[str] = set()
    top_risks: list[dict[str, Any]] = []

    for b in blast_radius:
        vid = b.get("vulnerability_id", "")
        if vid and vid in seen_ids:
            continue
        if vid:
            seen_ids.add(vid)
        sev = (b.get("severity") or "").lower()
        # Always count into exactly one bucket — unknown severities land in
        # ``unrated`` instead of being dropped (the 39-CVEs / 0-severities bug).
        severity[_bucket(sev, severity)] += 1
        is_kev = bool(b.get("cisa_kev") or b.get("is_kev"))
        if is_kev:
            kev += 1
        creds = b.get("exposed_credentials") or []
        if creds:
            credential_exposed += 1
        risk = b.get("risk_score")
        if risk is None:
            risk = (b.get("blast_score") or 0) / 10
        top_risks.append(
            {
                "vulnerability_id": vid,
                "package": b.get("package"),
                "severity": sev or "low",
                "risk_score": round(float(risk or 0), 1),
                "is_kev": is_kev,
                "cvss_score": b.get("cvss_score"),
                "epss_score": b.get("epss_score"),
                "affected_agents": list(b.get("affected_agents") or []),
                "affected_servers": list(b.get("affected_servers") or []),
                "impact_category": b.get("impact_category"),
                "fixed_version": b.get("fixed_version"),
            }
        )

    top_risks.sort(key=lambda r: r["risk_score"], reverse=True)
    # One source of truth: the CVE count is the histogram total, so the severity
    # strip and the headline number can never disagree.
    return {
        "severity": severity,
        "kev": kev,
        "credential_exposed": credential_exposed,
        "unique_cves": sum(severity.values()),
        "top_risks": top_risks[:10],
    }


def _rollup_from_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = cast(dict[str, Any], result.get("summary") or {})
    finding_summary = cast(dict[str, Any], result.get("finding_summary") or {})
    severity = _severity_from_summary(summary, finding_summary)
    # ``_severity_from_summary`` reconciles the histogram with the scalar total,
    # so the histogram sum is the single source of truth for the CVE count.
    unique_cves = sum(severity.values())
    return {
        "severity": severity,
        "kev": 0,
        "credential_exposed": 0,
        "unique_cves": unique_cves,
        "unique_packages": int(summary.get("unique_packages") or summary.get("total_packages") or 0),
        "top_risks": [],
    }


_SEVERITY_RISK_FLOOR: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.5,
}


_UNRATED_RISK_FLOOR = 0.5


def _row_risk_score(row: dict[str, Any]) -> float:
    """Comparable 0–10 risk for a top-risk entry, spine or hub-ingested.

    Prefers an explicit ``risk_score`` (the scan spine always sets one). A
    hub-ingested / bulk finding carries no ``risk_score`` and usually no
    reachability signal, so we derive a band-dominant blend: the finding's
    severity floor (:data:`_SEVERITY_RISK_FLOOR`) plus a small CVSS refinement
    (``cvss / 100``) that orders findings WITHIN a band without ever crossing it.
    That keeps a critical worst-first even when it carries no CVSS — the earlier
    CVSS-only fallback scored such a critical at 0.0, burying it below a
    medium@6.5. Result clamped to [0, 10].
    """
    risk = row.get("risk_score")
    if risk is not None:
        try:
            return round(min(10.0, max(0.0, float(risk or 0))), 1)
        except (TypeError, ValueError):
            return 0.0
    severity = str(row.get("severity") or "").strip().lower()
    floor = _SEVERITY_RISK_FLOOR.get(severity, _UNRATED_RISK_FLOOR)
    try:
        cvss = float(row.get("cvss_score") or 0.0)
    except (TypeError, ValueError):
        cvss = 0.0
    refine = min(max(cvss, 0.0), 10.0) / 100.0
    return round(min(10.0, max(0.0, floor + refine)), 1)


def _finding_top_risk(row: dict[str, Any]) -> dict[str, Any]:
    """Build a top-risk strip entry from a unified findings-spine or hub row."""
    raw_asset = row.get("asset")
    raw_evidence = row.get("evidence")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
    package = row.get("package")
    if not package and evidence.get("package_name"):
        package = str(evidence["package_name"])
    if package and package == evidence.get("package_name") and evidence.get("package_version"):
        package += f"@{evidence['package_version']}"
    if not package and asset.get("asset_type") == "package":
        package = asset.get("name")
    servers = list(row.get("affected_servers") or [])
    if not servers and asset.get("asset_type") == "mcp_server" and asset.get("name"):
        servers = [asset["name"]]
    return {
        "vulnerability_id": str(row.get("cve_id") or row.get("canonical_id") or row.get("id") or row.get("finding_id") or ""),
        "canonical_id": row.get("canonical_id"),
        "asset_id": asset.get("canonical_id") or asset.get("stable_id"),
        "affected_servers": servers,
        "package": package,
        "severity": (str(row.get("severity") or "").strip().lower() or "low"),
        "risk_score": _row_risk_score(row),
        "is_kev": bool(row.get("is_kev") or row.get("cisa_kev")),
        "cvss_score": row.get("cvss_score"),
        "epss_score": row.get("epss_score"),
        "affected_agents": list(row.get("affected_agents") or []),
        "impact_category": row.get("impact_category"),
        "fixed_version": row.get("fixed_version"),
    }


def _fold_findings(
    findings: list[Any],
    *,
    severity: dict[str, int],
    lanes: dict[str, dict[str, int]],
    lane_counts: dict[str, int],
    seen: set[str],
    top_risks: list[dict[str, Any]],
    failing_frameworks: set[str],
) -> tuple[int, int, int]:
    """Fold unified findings-spine rows into the shared estate accumulators.

    Every row is counted once into exactly one bucket of the all-domain severity
    histogram (the headline/grade basis) AND into EVERY coverage lens it belongs
    to (the coverage lanes are overlapping posture disciplines, not a partition —
    a repo dependency CVE counts under both ``vuln`` and ``aspm``). Because lanes
    overlap, the sum of lane counts is not the total; the histogram is the
    single source of truth for the headline. Returns
    ``(added, kev, credential_exposed)`` for this batch. A finding whose severity
    is critical/high marks each of its ``applicable_frameworks`` as failing
    (feeds the exec grade's compliance driver, #3962).
    """
    from agent_bom.compliance_coverage import normalize_framework_slug, scored_framework_slugs

    added = 0
    kev = 0
    credential_exposed = 0
    scored_slugs = scored_framework_slugs()
    for row in findings:
        if not isinstance(row, dict):
            continue
        identity = str(row.get("id") or row.get("canonical_id") or row.get("cve_id") or id(row))
        if identity in seen:
            continue
        seen.add(identity)
        bucket = _bucket(str(row.get("severity") or ""), severity)
        # All-domain histogram: once per finding (the headline/grade basis).
        severity[bucket] += 1
        # Coverage lanes: increment EVERY applicable lens (lanes overlap).
        for dom in _row_lenses(row):
            lanes[dom][bucket] += 1
            lane_counts[dom] += 1
        added += 1
        if bool(row.get("is_kev") or row.get("cisa_kev")):
            kev += 1
        if row.get("exposed_credentials"):
            credential_exposed += 1
        if bucket in ("critical", "high"):
            for slug in row.get("applicable_frameworks") or []:
                canonical = normalize_framework_slug(str(slug)) if slug else ""
                if canonical in scored_slugs:
                    failing_frameworks.add(canonical)
        top_risks.append(_finding_top_risk(row))
    return added, kev, credential_exposed


def _job_package_count(result: dict[str, Any]) -> int:
    """Count discovered packages across the scan's agents/servers."""
    packages = 0
    for agent in result.get("agents", []) or []:
        for server in agent.get("mcp_servers", []) or []:
            for pkg in server.get("packages", []) or []:
                if pkg.get("name"):
                    packages += 1
    return packages


def _row_domain(row: dict[str, Any]) -> str:
    """Return the security domain for a serialized finding row.

    Prefers the first-class ``security_domain`` field (set by
    ``Finding.to_dict``); falls back to the source/type mapping for legacy rows.
    ``vuln`` is the safe default for legacy CVE rows that predate the taxonomy.
    """
    from agent_bom.finding_scope import domain_for_row

    return domain_for_row(row) or "vuln"


def _row_lenses(row: dict[str, Any]) -> set[str]:
    """Overlapping coverage lenses for a row, guaranteeing the primary lane.

    The coverage lanes are posture lenses, not a partition — a repo dependency
    CVE counts under both ``vuln`` and ``aspm``. The primary lane (or the
    ``vuln`` default for legacy rows) is always included so every finding lands
    in at least one lane, while the all-domain histogram is still counted once
    per finding.
    """
    from agent_bom.finding_scope import lenses_for_row

    lenses = set(lenses_for_row(row))
    lenses.add(_row_domain(row))
    return {dom for dom in lenses if dom in _COVERAGE_DOMAINS}


def _merge_top_risks(*groups: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Merge identical canonical occurrences, preserving unknown identities.

    A CVE identifies a weakness, not the runtime occurrence bearing it. Scope,
    package/version and agents remain part of the key even if a producer reuses
    a canonical id. Missing canonical identity cannot prove equivalence.
    """
    best_by_id: dict[tuple[Any, ...], dict[str, Any]] = {}
    keyless: list[dict[str, Any]] = []
    for group in groups:
        for entry in group:
            canonical_id = entry.get("canonical_id")
            agents = entry.get("affected_agents") or []
            servers = entry.get("affected_servers") or []
            if (
                not isinstance(canonical_id, str)
                or not canonical_id.strip()
                or any(value is not None and not isinstance(value, str) for value in (entry.get("asset_id"), entry.get("package")))
                or not isinstance(agents, list)
                or not isinstance(servers, list)
                or any(not isinstance(name, str) for name in [*agents, *servers])
            ):
                keyless.append(entry)
                continue
            key = (
                canonical_id,
                entry.get("vulnerability_id"),
                entry.get("asset_id"),
                entry.get("package"),
                tuple(sorted(agents)),
                tuple(sorted(servers)),
            )
            existing = best_by_id.get(key)
            if existing is None or float(entry.get("risk_score") or 0.0) > float(existing.get("risk_score") or 0.0):
                best_by_id[key] = entry
    merged = [*best_by_id.values(), *keyless]
    merged.sort(key=lambda r: float(r.get("risk_score") or 0.0), reverse=True)
    return merged[:limit]


def _combined_severity(scan_severity: dict[str, int], hub_severity: dict[str, int]) -> dict[str, int]:
    """Merge scan + hub-ingested severity into the five reconciled buckets.

    The hub histogram carries bands the exec-score model doesn't rate —
    ``info``/``unknown``/``none`` and any vendor-specific label — which ALL fold
    into ``unrated`` so nothing is dropped and the merged buckets still sum to the
    true counted total (the same invariant PR1's coverage lanes hold). Folding
    only ``info``/``unknown`` previously dropped a ``none``-severity hub finding
    from ``total`` while /v1/findings still counted it (``none`` is an accepted
    findings filter) — an exec/drill mismatch (#3961).
    """
    merged = {key: int(scan_severity.get(key, 0) or 0) for key in _ALL_SEVERITY_KEYS}
    for band, count in hub_severity.items():
        key = str(band).strip().lower()
        merged[key if key in _SEVERITY_KEYS else _UNRATED_KEY] += int(count or 0)
    return merged


def _reconciled_exec_counts(estate: dict[str, Any], hub_severity: dict[str, int], hub_kev: int = 0) -> dict[str, int]:
    """The single exec-facing severity source of truth (#3961).

    Both the ``/v1/overview`` headline and ``/v1/posture/counts`` derive their
    critical/high/… from THIS reconciliation of the canonical, windowed scan
    current state with hub-ingested current evidence. The honest ``unrated``
    bucket is carried through and the buckets sum to ``total`` (no silent drop).
    ``kev`` reconciles the scan-lane rollup with hub-ingested KEV findings so a
    connector/pushed KEV finding moves the headline, not just the drill.
    """
    combined = _combined_severity(estate["severity"], hub_severity)
    return {
        "critical": combined["critical"],
        "high": combined["high"],
        "medium": combined["medium"],
        "low": combined["low"],
        "unrated": combined[_UNRATED_KEY],
        "total": sum(combined.values()),
        "kev": int(estate.get("kev", 0) or 0) + int(hub_kev or 0),
        "credential_exposed": int(estate.get("credential_exposed", 0) or 0),
    }


def _current_open_scan_findings(jobs: list[Any]) -> list[dict[str, Any]]:
    """The same executed scan, time window and lifecycle basis as the drill."""
    from agent_bom.api.scan_finding_read import current_open_scan_findings

    return current_open_scan_findings(jobs)


def _current_scan_severity(jobs: list[Any]) -> dict[str, int]:
    """Authoritative executed-scan histogram for executive posture surfaces."""
    severity = _empty_severity()
    for row in _current_open_scan_findings(jobs):
        severity[_bucket(str(row.get("severity") or ""), severity)] += 1
    return severity


def _fold_current_coverage(lanes: dict[str, dict[str, int]], row: dict[str, Any]) -> None:
    from agent_bom.api.overview_cve_counts import add_cve_finding
    from agent_bom.finding_scope import lenses_for_row

    if "_cves" in lanes:
        add_cve_finding(lanes["_cves"], row)

    # Match the domain drill exactly; an unclassified row is not invented as a CVE.
    for domain in lenses_for_row(row):
        if domain in lanes:
            bands = lanes[domain]
            bands[_bucket(str(row.get("severity") or ""), bands)] += 1


def _exec_estate(estate: dict[str, Any], jobs: list[Any]) -> dict[str, Any]:
    """Overlay canonical current scan counts without changing domain history."""
    findings = _current_open_scan_findings(jobs)
    severity = _empty_severity()
    for row in findings:
        severity[_bucket(str(row.get("severity") or ""), severity)] += 1
    return {
        **estate,
        "severity": severity,
        "kev": sum(bool(row.get("is_kev") or row.get("cisa_kev")) for row in findings),
        "credential_exposed": sum(bool(row.get("exposed_credentials")) for row in findings),
    }
