"""Output html sections findings helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.core.risk_display import risk_label
from agent_bom.core.severity import (
    severity_policy_rank,
)
from agent_bom.finding import FindingType
from agent_bom.models import AIBOMReport, BlastRadius
from agent_bom.output.exposure_path import exposure_path_brief_for_finding
from agent_bom.output.finding_views import (
    cve_findings,
    evidence,
    exploit_likelihood_value,
    package_name,
    package_version,
    ranked_cve_findings,
    reachability_label,
    severity_value,
    workflow_status,
)
from agent_bom.output.html._common import (
    _PAGE_SIZE,
    _SEV_COLOR,
    _esc,
    _finding_sev_badge,
    _sev_badge,
)

if TYPE_CHECKING:
    from agent_bom.finding import Finding

# Reachability cell colors, keyed by the state from ``reachability_label``.
_REACH_COLOR = {"reachable": "#f87171", "unreachable": "#64748b", "unknown": "#475569"}


def _pager_controls(table_id: str, total: int, page_size: int = _PAGE_SIZE) -> str:
    """Server-rendered pagination bar bound to a table by ``data-pager``.

    Rendered for every findings table so the controls exist in the static file
    (and in tests); the paginator JS wires the buttons and hides the whole bar
    when the filtered set fits on a single page.
    """
    return (
        f'<div class="pager" data-pager="{table_id}" data-page-size="{page_size}">'
        '<button class="pager-btn" data-act="first" title="First page">&laquo;</button>'
        '<button class="pager-btn" data-act="prev" title="Previous page">&lsaquo; Prev</button>'
        f'<span class="pager-info">1&ndash;{min(page_size, total)} of {total}</span>'
        '<button class="pager-btn" data-act="next" title="Next page">Next &rsaquo;</button>'
        '<button class="pager-btn" data-act="last" title="Last page">&raquo;</button>'
        '<span class="pager-sep"></span>'
        '<label class="pager-size-label">Rows'
        '<select class="pager-size">'
        '<option value="25">25</option>'
        f'<option value="50"{" selected" if page_size == 50 else ""}>50</option>'
        '<option value="100">100</option>'
        '<option value="250">250</option>'
        "</select></label>"
        "</div>"
    )


def _vuln_table(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"],
    *,
    findings: list["Finding"] | None = None,
) -> str:
    findings = findings if findings is not None else cve_findings(report, blast_radii)
    if not findings:
        return '<div class="empty-state">&#x2705; No vulnerabilities found in scanned packages.</div>'

    has_missing = any(not finding.cvss_score or not finding.description for finding in findings)
    hint = ""
    if has_missing:
        hint = (
            '<div class="hint-box">'
            "&#x1f4a1; <strong>Some entries are missing CVSS scores or descriptions.</strong> "
            "Run with <code>--enrich</code> to fetch full NVD metadata, CVSS 3.x vectors, EPSS, and CISA KEV status."
            "</div>"
        )

    sorted_findings = sorted(
        findings,
        key=lambda finding: severity_policy_rank(severity_value(finding)),
        reverse=True,
    )
    # Advisory AI-triage assessments joined by the finding id they describe.
    ai_assessments = {assessment.finding_id: assessment for assessment in getattr(report, "ai_finding_assessments", []) or []}
    rows = [_vuln_row(idx, finding, ai_assessments) for idx, finding in enumerate(sorted_findings)]

    headers = ["Vuln ID", "Severity", "Package", "CVSS", "EPSS", "KEV", "Reach", "Fix", "Affected Agents", "Exposed Creds", "Summary"]

    filter_bar = (
        '<div class="vuln-filter-bar" style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;'
        'margin-bottom:14px;padding:12px 16px;background:#0f172a;border-radius:8px;border:1px solid #1e293b">'
        '<span style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em;font-weight:700">Filter:</span>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#fca5a5;cursor:pointer">'
        '<input type="checkbox" class="vuln-sev-filter" value="critical" checked> Critical</label>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#fb923c;cursor:pointer">'
        '<input type="checkbox" class="vuln-sev-filter" value="high" checked> High</label>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#fbbf24;cursor:pointer">'
        '<input type="checkbox" class="vuln-sev-filter" value="medium" checked> Medium</label>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#94a3b8;cursor:pointer">'
        '<input type="checkbox" class="vuln-sev-filter" value="low" checked> Low</label>'
        '<span style="width:1px;height:18px;background:#334155"></span>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#fca5a5;cursor:pointer">'
        '<input type="checkbox" id="kevToggle"> KEV only</label>'
        '<span style="width:1px;height:18px;background:#334155"></span>'
        '<input type="text" id="vulnSearch" placeholder="Search vulns&hellip;" '
        'style="padding:6px 10px;background:#1e293b;border:1px solid #334155;border-radius:6px;'
        'color:#e2e8f0;font-size:.78rem;width:160px;outline:none">'
        "</div>"
    )

    return (
        hint
        + filter_bar
        + '<div class="table-wrap"><table class="data-table sortable paginated" id="vulnTable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + "</tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
        + _pager_controls("vulnTable", len(rows))
    )


def _blast_table(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"],
    *,
    findings: list["Finding"] | None = None,
) -> str:
    findings = findings if findings is not None else cve_findings(report, blast_radii)
    if not findings:
        return ""
    sorted_findings = sorted(findings, key=lambda finding: float(finding.risk_score or 0.0), reverse=True)
    rows = []
    for i, finding in enumerate(sorted_findings, 1):
        color = _SEV_COLOR.get(severity_value(finding), "#6b7280")
        bar_w = int((finding.risk_score or 0.0) * 9)
        ai_badge = '<span class="badge-ai">AI</span>' if finding.ai_risk_context else ""
        kev_badge = '<span class="badge-kev">KEV</span>' if finding.is_kev else ""
        fix = (
            f'<code style="color:#4ade80;font-size:.8rem">{_esc(finding.fixed_version)}</code>'
            if finding.fixed_version
            else '<span style="color:#475569">&mdash;</span>'
        )
        vuln_id = finding.cve_id or finding.id
        rows.append(
            f"<tr>"
            f'<td style="color:#475569;font-weight:600">#{i}</td>'
            f'<td><code class="vuln-id">{_esc(vuln_id)}</code></td>'
            f"<td>{_finding_sev_badge(finding)}</td>"
            f"<td>"
            f'<div style="display:flex;align-items:center;gap:8px">'
            f'<div style="background:#0f172a;border-radius:3px;height:5px;width:90px">'
            f'<div style="background:{color};border-radius:3px;height:5px;width:{bar_w}px"></div></div>'
            f'<strong style="color:{color}">{_esc(risk_label(finding.risk_score))}</strong></div>'
            f"</td>"
            f'<td style="text-align:center;color:#e2e8f0">{len(finding.affected_agents)}</td>'
            f'<td style="text-align:center;color:#fbbf24">{len(finding.exposed_credentials)}</td>'
            f'<td style="text-align:center;color:#94a3b8">{len(finding.exposed_tools)}</td>'
            f"<td>{ai_badge}{kev_badge}</td>"
            f"<td>{fix}</td>"
            f"</tr>"
        )
    headers = ["#", "Vuln ID", "Severity", "Blast Score (0&ndash;10)", "Agents Hit", "Creds Exposed", "Tools Reachable", "Flags", "Fix"]
    return (
        '<div class="table-wrap"><table class="data-table sortable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _exposure_path_section(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"],
    *,
    findings: list["Finding"] | None = None,
) -> str:
    findings = (
        sorted(findings, key=lambda finding: float(finding.risk_score or 0.0), reverse=True)[:10]
        if findings is not None
        else ranked_cve_findings(report, blast_radii)
    )
    if not findings:
        return ""
    cards = []
    for rank, finding in enumerate(findings, 1):
        brief = exposure_path_brief_for_finding(finding, rank=rank)
        sev = str(finding.effective_severity() or finding.severity or "unknown").lower()
        color = _SEV_COLOR.get(sev, "#6b7280")
        cards.append(
            '<div class="exposure-path-card">'
            f'<div class="path-rank" style="border-color:{color};color:{color}">#{_esc(brief["rank"])}</div>'
            '<div class="path-body">'
            f'<div class="path-title">{_esc(brief["path"])}</div>'
            f'<div class="path-summary">{_esc(brief["why"])}</div>'
            '<div class="path-meta">'
            f'<span style="color:{color};font-weight:700">{_esc(brief["severity"])}</span>'
            f"<span>risk {_esc(brief['risk'])}</span>"
            f"<span>{_esc(brief['proof'])}</span>"
            f"</div>"
            f'<div class="path-fix">{_esc(brief["fix"])}</div>'
            "</div>"
            "</div>"
        )
    return "".join(cards)


def _remediation_list(findings: list["Finding"]) -> str:
    if not findings:
        return '<p style="color:#4ade80">&#x2705; Nothing to remediate.</p>'
    with_fix = sorted(
        [finding for finding in findings if finding.fixed_version],
        key=lambda finding: float(finding.risk_score or 0.0),
        reverse=True,
    )
    no_fix = [finding for finding in findings if not finding.fixed_version]
    items = []
    for finding in with_fix:
        creds_note = (
            f' &middot; frees <strong style="color:#fbbf24">{len(finding.exposed_credentials)}</strong> credential(s)'
            if finding.exposed_credentials
            else ""
        )
        items.append(
            f'<div class="remediation-item">'
            f'<div style="flex-shrink:0;padding-top:1px">{_finding_sev_badge(finding)}</div>'
            f'<div style="flex:1">'
            f'<div style="color:#e2e8f0;font-weight:600">{_esc(package_name(finding))}'
            f'<span style="color:#475569;font-weight:400">@{_esc(package_version(finding))}</span></div>'
            f'<div style="font-size:.8rem;color:#64748b;margin-top:3px">'
            f'<code class="vuln-id">{_esc(finding.cve_id or finding.title)}</code>'
            f' &middot; upgrade to <code style="color:#4ade80">{_esc(finding.fixed_version)}</code>'
            f" &middot; protects <strong>{len(finding.affected_agents)}</strong> agent(s)"
            f"{creds_note}"
            f"</div></div>"
            f'<div style="flex-shrink:0;color:#475569;font-size:.78rem;padding-top:3px">score&nbsp;{_esc(risk_label(finding.risk_score))}</div>'
            f"</div>"
        )
    nf_html = ""
    if no_fix:
        nf_rows = "".join(
            f'<div style="padding:9px 0;border-bottom:1px solid #1e293b;font-size:.82rem">'
            f"{_finding_sev_badge(finding)} "
            f'<code class="vuln-id">{_esc(finding.cve_id or finding.title)}</code> &mdash; '
            f'<strong style="color:#e2e8f0">{_esc(package_name(finding))}</strong>@{_esc(package_version(finding))}'
            f' &mdash; <span style="color:#475569">no fix available &mdash; monitor upstream</span></div>'
            for finding in no_fix
        )
        nf_html = '<div style="margin-top:20px"><div class="subsection-label">No Fix Available</div>' + nf_rows + "</div>"
    return "".join(items) + nf_html


def _workload_runtime_evidence_hint(finding: object) -> str:
    """Compact HTML badge for CWPP runtime/EDR evidence. Never labels absence as clean."""
    payload = getattr(finding, "workload_runtime_evidence", None)
    if not isinstance(payload, dict) or not payload:
        return ""
    state = str(payload.get("state") or "").strip() or "unknown"
    label_map = {
        "runtime_ioc_observed": "Runtime IOC",
        "runtime_alert_observed": "Runtime alert",
        "runtime_activity_observed": "Runtime observed",
        "no_runtime_signal": "No runtime signal",
    }
    label = label_map.get(state, f"Runtime {state.replace('_', ' ')}")
    color = {
        "runtime_ioc_observed": "#f87171",
        "runtime_alert_observed": "#fb923c",
        "runtime_activity_observed": "#38bdf8",
        "no_runtime_signal": "#94a3b8",
    }.get(state, "#94a3b8")
    title = "CWPP runtime/EDR evidence — additive; not a clean-workload assertion"
    return (
        f'<br><span class="workload-runtime-evidence" data-state="{_esc(state)}" '
        f'title="{title}" style="font-size:.6rem;color:{color}">{_esc(label)}</span>'
    )


def _non_cve_findings(report: "AIBOMReport") -> list["Finding"]:
    """Return unified findings not already represented in the CVE or CIS tables.

    Cloud CIS benchmark FAILures are lifted into the unified stream by
    ``to_findings()`` AND rendered per-check by the dedicated CIS Benchmark
    Posture table (``_CIS_CLOUD_LABELS``). Skip the unified copy for any
    provider that table covers so each failed check renders exactly once (no
    double-emit). Snowflake governance findings are also ``CIS_FAIL`` but carry
    no ``benchmark`` marker and have no dedicated table, so they stay here.
    """
    findings: list[Finding] = []
    for finding in report.to_findings():
        if finding.finding_type == FindingType.CVE:
            continue
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        if (
            finding.finding_type in {FindingType.CIS_FAIL, FindingType.CIS_ERROR}
            and evidence.get("benchmark") == "CIS"
            and evidence.get("provider") in _CIS_CLOUD_LABELS
        ):
            continue
        findings.append(finding)
    return findings


def _policy_findings_section(findings: list["Finding"]) -> str:
    """Render unified non-CVE findings with asset, source, and evidence context."""
    if not findings:
        return ""

    rows = _policy_finding_rows(findings)

    headers = ["Severity", "Type", "Asset", "Finding", "Source", "Evidence", "Remediation"]
    header_html = "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
    severity_filters = "".join(
        f'<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:{color};cursor:pointer">'
        f'<input type="checkbox" class="policy-sev-filter" value="{sev}" checked> {label}</label>'
        for sev, label, color in (
            ("critical", "Critical", "#fca5a5"),
            ("high", "High", "#fb923c"),
            ("medium", "Medium", "#fbbf24"),
            ("low", "Low", "#94a3b8"),
            ("unknown", "Unknown", "#94a3b8"),
        )
    )
    finding_types = sorted({finding.finding_type.value for finding in findings})
    type_options = "".join(f'<option value="{_esc(ftype)}">{_esc(ftype)}</option>' for ftype in finding_types)
    asset_types = sorted({finding.asset.asset_type for finding in findings if finding.asset.asset_type})
    asset_options = "".join(f'<option value="{_esc(asset_type)}">{_esc(asset_type)}</option>' for asset_type in asset_types)
    filter_bar = (
        '<div class="policy-filter-bar" style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;'
        'margin-bottom:14px;padding:12px 16px;background:#0f172a;border-radius:8px;border:1px solid #1e293b">'
        '<span style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em;font-weight:700">Filter:</span>'
        f"{severity_filters}"
        '<span style="width:1px;height:18px;background:#334155"></span>'
        '<select id="policyTypeFilter" style="padding:6px 10px;background:#1e293b;border:1px solid #334155;border-radius:6px;'
        'color:#e2e8f0;font-size:.78rem;outline:none"><option value="">All types</option>'
        f"{type_options}</select>"
        '<select id="policyAssetFilter" style="padding:6px 10px;background:#1e293b;border:1px solid #334155;border-radius:6px;'
        'color:#e2e8f0;font-size:.78rem;outline:none"><option value="">All assets</option>'
        f"{asset_options}</select>"
        '<input type="text" id="policySearch" placeholder="Search policy findings&hellip;" '
        'style="padding:6px 10px;background:#1e293b;border:1px solid #334155;border-radius:6px;'
        'color:#e2e8f0;font-size:.78rem;width:220px;outline:none">'
        '<span id="policyVisibleCount" style="margin-left:auto;font-size:.72rem;color:#64748b"></span>'
        "</div>"
    )
    return (
        f'<section id="policyfindings">'
        f'<div class="sec-title">&#x1f6e1;&#xfe0f; Policy &amp; Security Findings'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(findings)}</sup></div>'
        f'<div class="panel">'
        f'<div class="hint-box">'
        f"Unified non-CVE findings from scanners, policy checks, runtime controls, and MCP intelligence. "
        f"These are the same findings emitted in JSON and SARIF."
        f"</div>"
        f"{filter_bar}"
        f'<div class="table-wrap"><table class="data-table sortable paginated" id="policyFindingsTable">'
        f"<thead><tr>{header_html}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
        f"{_pager_controls('policyFindingsTable', len(rows))}"
        f"</div></section>"
    )


_CIS_CLOUD_LABELS = {
    "aws": ("AWS", "cis_benchmark_data"),
    "azure": ("Azure", "azure_cis_benchmark_data"),
    "gcp": ("GCP", "gcp_cis_benchmark_data"),
    "snowflake": ("Snowflake", "snowflake_cis_benchmark_data"),
    "databricks": ("Databricks Security Best Practices", "databricks_security_data"),
}


def _vuln_metric_cells(finding: Finding) -> tuple[str, str, str, str, str, str, str, str, str]:
    sev = severity_value(finding)
    color = _SEV_COLOR.get(sev, "#6b7280")
    cvss_bar = ""
    if finding.cvss_score:
        pct = int(finding.cvss_score * 10)
        cvss_bar = (
            f'<div style="display:flex;align-items:center;gap:6px">'
            f'<div style="background:#0f172a;border-radius:3px;height:4px;width:52px;flex-shrink:0">'
            f'<div style="background:{color};border-radius:3px;height:4px;width:{pct}%"></div></div>'
            f'<strong style="color:{color}">{finding.cvss_score:.1f}</strong></div>'
        )
    else:
        cvss_bar = '<span style="color:#334155">&mdash;</span>'
    epss = f"{finding.epss_score:.1%}" if finding.epss_score else '<span style="color:#334155">&mdash;</span>'
    exploit_level = exploit_likelihood_value(finding)
    kev_due = evidence(finding, "kev_due_date", "") if finding.is_kev else ""
    kev_due_attr = f' data-kev-due="{_esc(kev_due)}"' if kev_due else ""
    if finding.is_kev:
        kev = '<span class="badge-kev" title="CISA Known Exploited Vulnerability">KEV</span>'
        if kev_due:
            # BOD 22-01 remediation deadline — the actionable half of a KEV
            # hit, and the only part that carries a date.
            kev += (
                f'<div style="font-size:.6rem;color:#94a3b8;margin-top:2px" '
                f'title="CISA BOD 22-01 remediation due date">due {_esc(kev_due)}</div>'
            )
    elif exploit_level == "likely_exploited":
        kev = '<span class="badge-exploit-likely" title="EPSS ≥ 0.5 or percentile ≥ 95 — exploitation likely">EXPL</span>'
    elif exploit_level == "public_exploit":
        kev = '<span class="badge-exploit-public" title="EPSS percentile ≥ 80 — public exploit code">PoC</span>'
    else:
        kev = '<span style="color:#334155">&mdash;</span>'
    fix = (
        f'<code style="color:#4ade80">{_esc(finding.fixed_version)}</code>'
        if finding.fixed_version
        else '<span style="color:#475569">No fix</span>'
    )
    reach_label, reach_state = reachability_label(finding)
    reach_color = _REACH_COLOR.get(reach_state, "#475569")
    reach_title = {
        "reachable": "Vulnerable code is reached from an entrypoint",
        "unreachable": "Package present but not reached from any entrypoint",
        "unknown": "Reachability engine did not produce a verdict",
    }.get(reach_state, "")
    reach_cell = (
        f'<span class="reach-badge" data-reach="{reach_state}" title="{reach_title}" '
        f'style="font-size:.68rem;color:{reach_color}">{reach_label}</span>'
    )
    return sev, cvss_bar, epss, exploit_level, kev_due_attr, kev, fix, reach_state, reach_cell


def _vuln_summary(finding: Finding, ai_assessments: dict[str, Any]) -> str:
    summary_text = (finding.description or "")[:90]
    summary = _esc(summary_text) if summary_text else '<span style="color:#475569;font-style:italic">Run --enrich</span>'
    workflow_parts: list[str] = []
    if finding.owner:
        workflow_parts.append(f"Owner: {_esc(finding.owner)}")
    sla_due = finding.to_dict().get("sla_due_at")
    if sla_due:
        workflow_parts.append(f"SLA: {_esc(sla_due)}")
    status = workflow_status(finding)
    if status:
        workflow_parts.append(f"Status: {_esc(status)}")
    if workflow_parts:
        summary += (
            '<div class="finding-workflow" style="margin-top:4px;font-size:.66rem;color:#a7f3d0">'
            + " &middot; ".join(workflow_parts)
            + "</div>"
        )
    assessment = ai_assessments.get(finding.id)
    if assessment is not None:
        summary += (
            f'<div class="ai-triage" style="margin-top:4px;font-size:.66rem;color:#a5b4fc">'
            f'<span class="badge-ai" title="AI triage (advisory)">AI</span> '
            f"{_esc(assessment.classification)} "
            f'<span style="color:#94a3b8">&middot; FP&nbsp;likelihood: {_esc(assessment.false_positive_likelihood)}</span>'
            f"</div>"
        )
    return summary


def _vuln_row(idx: int, finding: Finding, ai_assessments: dict[str, Any]) -> str:
    sev, cvss_bar, epss, exploit_level, kev_due_attr, kev, fix, reach_state, reach_cell = _vuln_metric_cells(finding)
    summary = _vuln_summary(finding, ai_assessments)
    agents_s = ", ".join(_esc(name) for name in finding.affected_agents) or "<span style='color:#334155'>&mdash;</span>"
    creds_s = (
        " ".join(f'<code style="color:#fbbf24">{_esc(c)}</code>' for c in finding.exposed_credentials)
        or "<span style='color:#334155'>&mdash;</span>"
    )
    vendor_sev = finding.vendor_severity
    vendor_hint = ""
    if vendor_sev and vendor_sev.lower() != sev:
        vendor_hint = f'<br><span style="font-size:.62rem;color:#94a3b8;font-style:italic">vendor: {_esc(vendor_sev)}</span>'
    tier = evidence(finding, "match_confidence_tier", None)
    tier_hint = ""
    if tier:
        _tier_color = "#f59e0b" if tier in {"nvd_cpe_candidate", "ambiguous_distro_release", "unverified_range"} else "#64748b"
        tier_hint = (
            f'<br><span class="match-tier" data-tier="{_esc(tier)}" '
            f'title="match confidence: {_esc(tier)}" '
            f'style="font-size:.6rem;color:{_tier_color}">{_esc(str(tier).replace("_", " "))}</span>'
        )
    runtime_hint = _workload_runtime_evidence_hint(finding)
    vuln_id = finding.cve_id or finding.id
    pkg_name = package_name(finding)
    pkg_version = package_version(finding)
    pg_cls = " pg-hidden" if idx >= _PAGE_SIZE else ""
    return (
        f'<tr class="pg-row{pg_cls}" data-severity="{sev}" data-kev="{"1" if finding.is_kev else "0"}"{kev_due_attr} '
        f'data-exploit-likelihood="{exploit_level}" '
        f'data-reachability="{reach_state}" '
        f'data-match-tier="{_esc(tier or "")}" '
        f'data-cvss="{finding.cvss_score if finding.cvss_score else 0}">'
        f'<td><code class="vuln-id">{_esc(vuln_id)}</code>{tier_hint}{runtime_hint}</td>'
        f"<td>{_finding_sev_badge(finding)}{vendor_hint}</td>"
        f'<td><strong style="color:#e2e8f0">{_esc(pkg_name)}</strong>'
        f'<span style="color:#475569;font-size:.78rem">@{_esc(pkg_version)}</span></td>'
        f"<td>{cvss_bar}</td>"
        f'<td style="text-align:center;font-size:.82rem;color:#94a3b8">{epss}</td>'
        f'<td style="text-align:center">{kev}</td>'
        f'<td style="text-align:center">{reach_cell}</td>'
        f"<td>{fix}</td>"
        f'<td style="font-size:.78rem;color:#94a3b8">{agents_s}</td>'
        f'<td style="font-size:.78rem">{creds_s}</td>'
        f'<td style="font-size:.75rem;color:#64748b;max-width:180px">{summary}</td>'
        f"</tr>"
    )


def _policy_finding_rows(findings: list[Finding]) -> list[str]:
    rows = []
    for idx, finding in enumerate(sorted(findings, key=lambda f: severity_policy_rank(str(f.severity)), reverse=True)):
        sev = str(finding.severity or "unknown").lower()
        title = finding.title or finding.description or finding.finding_type.value
        asset_label = finding.asset.name or finding.asset.identifier or "unknown asset"
        location = (
            f'<br><code style="color:#64748b;font-size:.72rem">{_esc(finding.asset.location)}</code>' if finding.asset.location else ""
        )
        description = finding.description or finding.remediation_guidance or ""
        evidence_items = [f"{_esc(key)}={_esc(value)}" for key, value in finding.evidence.items() if value not in (None, "", [], {})][:4]
        evidence = (
            "<br>".join(f'<code style="color:#94a3b8;font-size:.72rem">{item}</code>' for item in evidence_items)
            if evidence_items
            else '<span style="color:#334155">&mdash;</span>'
        )
        runtime_hint = _workload_runtime_evidence_hint(finding)
        if runtime_hint:
            evidence = f"{evidence}{runtime_hint}"
        remediation = finding.remediation_guidance or ""
        description_html = f'<br><span style="color:#94a3b8">{_esc(description)}</span>' if description else ""
        remediation_html = _esc(remediation) if remediation else '<span style="color:#334155">&mdash;</span>'
        pg_cls = " pg-hidden" if idx >= _PAGE_SIZE else ""
        rows.append(
            f'<tr class="pg-row{pg_cls}" data-severity="{sev}" data-type="{_esc(finding.finding_type.value)}" '
            f'data-source="{_esc(finding.source.value)}" data-asset-type="{_esc(finding.asset.asset_type)}">'
            f"<td>{_sev_badge(sev)}</td>"
            f'<td><code style="color:#c4b5fd;font-size:.75rem">{_esc(finding.finding_type.value)}</code></td>'
            f'<td><strong style="color:#e2e8f0">{_esc(asset_label)}</strong>'
            f'<br><span style="color:#64748b;font-size:.72rem">{_esc(finding.asset.asset_type)}</span>{location}</td>'
            f'<td style="font-size:.82rem;color:#cbd5e1;max-width:260px"><strong>{_esc(title)}</strong>'
            f"{description_html}</td>"
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(finding.source.value)}</code></td>'
            f'<td style="font-size:.75rem;color:#94a3b8;max-width:220px">{evidence}</td>'
            f'<td style="font-size:.75rem;color:#4ade80;max-width:220px">{remediation_html}</td>'
            "</tr>"
        )
    return rows
