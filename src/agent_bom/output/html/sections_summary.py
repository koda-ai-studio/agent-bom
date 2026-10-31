"""Output html sections summary helpers."""

from __future__ import annotations

from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.finding import Finding
from agent_bom.models import AIBOMReport
from agent_bom.output.finding_views import (
    severity_value,
)
from agent_bom.output.graph_inventory import _static_inventory
from agent_bom.output.html._common import (
    _esc,
    _sev_badge,
)

# ─── HTML sections ────────────────────────────────────────────────────────────


def _delta_banner(report: "AIBOMReport") -> str:
    """Render a delta mode info banner when the scan used --delta."""
    scan_json = getattr(report, "_cached_json", None)
    delta = (scan_json or {}).get("delta") if scan_json else None
    if not delta or not delta.get("enabled"):
        return ""
    new_count = delta.get("new_count", 0)
    pre_count = delta.get("pre_existing_count", 0)
    baseline = _esc(str(delta.get("baseline_path") or ""))
    parts = []
    if new_count:
        parts.append(f"<b>{new_count}</b> new finding(s)")
    if pre_count:
        parts.append(f"<b>{pre_count}</b> pre-existing (suppressed from exit code)")
    body = " &middot; ".join(parts) if parts else "No new findings"
    baseline_html = f' &nbsp;<span style="color:#94a3b8;font-size:.75rem">baseline: {baseline}</span>' if baseline else ""
    return (
        '<div style="background:#1e3a5f;border:1px solid #2563eb;border-radius:8px;'
        'padding:10px 16px;margin-bottom:12px;font-size:.85rem;color:#93c5fd">'
        f"&#x1f504; <b>Delta mode</b>: {body}{baseline_html}"
        "</div>"
    )


def _warn_gate_banner(report: "AIBOMReport") -> str:
    """Render a warn-gate banner when findings triggered the warn threshold."""
    scan_json = getattr(report, "_cached_json", None)
    if not scan_json:
        return ""
    if scan_json.get("warn_gate_status") != "warn":
        return ""
    count = scan_json.get("warn_gate_count", 0)
    sev = _esc(str(scan_json.get("warn_gate_severity") or ""))
    return (
        '<div style="background:#422006;border:1px solid #d97706;border-radius:8px;'
        'padding:10px 16px;margin-bottom:12px;font-size:.85rem;color:#fcd34d">'
        f"&#x26a0;&#xfe0f; <b>Warn gate triggered</b>: {count} finding(s) at or above "
        f"<b>{sev}</b> severity &mdash; exit 0 (warning only, not a hard failure)"
        "</div>"
    )


def _scan_outcome_banner(report: "AIBOMReport") -> str:
    """Render an explicit coverage banner so empty partial scans are not CLEAN."""
    run = effective_scan_run(report)
    if run.outcome is ScanOutcome.COMPLETE:
        return ""
    failed = run.outcome is ScanOutcome.FAILED
    color = "#dc2626" if failed else "#d97706"
    label = "SCAN FAILED" if failed else "PARTIAL COVERAGE"
    issues = "".join(f"<li>{_esc(issue.source)}: {_esc(issue.message)}</li>" for issue in run.issues)
    return (
        f'<div style="background:{color}18;border:1px solid {color};border-radius:8px;'
        "padding:10px 16px;margin-bottom:12px;font-size:.85rem;"
        f'color:{color}">&#x26a0;&#xfe0f; <b>{label}</b>: this report does not represent complete '
        f"coverage. A low or zero finding count is not a clean bill of health."
        f'<ul style="margin:6px 0 0 18px">{issues}</ul></div>'
    )


def _headline_row(finding: "Finding") -> dict[str, object]:
    from agent_bom.graph.sla import finding_sla_fields

    sla = finding_sla_fields(
        {
            "severity": finding.effective_severity(),
            "first_seen": finding.first_seen,
            "evidence": finding.evidence,
            "sla_due_at": finding.sla_due_at,
            "sla_due_at_source": finding.sla_due_at_source or ("explicit" if finding.sla_due_at is not None else None),
        }
    )
    return {
        "id": finding.vulnerability_id or finding.id,
        "title": finding.title,
        "severity": severity_value(finding),
        "risk_score": finding.risk_score,
        "affected_agents": finding.affected_agents
        or ([finding.asset.name] if finding.asset.asset_type == "agent" and finding.asset.name else []),
        "owner": finding.owner,
        "sla_due_at": sla.get("sla_due_at"),
        "suppressed": bool(finding.suppressed),
    }


def _executive_headline_section(findings: list["Finding"], policy_findings: list["Finding"]) -> str:
    """Leadership paragraph over every finding in the report, with owner/SLA as recorded."""
    from agent_bom.output.executive_headline import build_executive_headline

    headline = build_executive_headline((_headline_row(finding) for finding in [*findings, *policy_findings]), include_risk_sentences=False)
    rows = "".join(
        '<li class="headline-risk">'
        f"<h3>{_esc(risk.title)}</h3>"
        f'<div class="headline-risk-meta">{_sev_badge(_esc(risk.severity))}</div>'
        "<details><summary>Context and ownership</summary><dl>"
        f"<dt>Recorded context</dt><dd>{_esc(', '.join(risk.affected_agents) or 'none recorded')}</dd>"
        f"<dt>Risk score</dt><dd>{f'{risk.risk_score:.1f}/10' if risk.risk_score is not None else 'unscored'}</dd>"
        f"<dt>Owner</dt><dd>{_esc(risk.owner or 'unassigned')}</dd>"
        f"<dt>SLA target</dt><dd>{_esc(risk.sla_due_at or 'no SLA set')}</dd>"
        '</dl><p class="headline-risk-note">SLA targets may come from configured policy.</p></details>'
        "</li>"
        for risk in headline.top_risks
    )
    risks = f'<ul class="headline-risks" aria-label="Top risks">{rows}</ul>' if rows else ""
    return (
        '<section id="executive-headline">'
        '<div class="sec-title">Executive headline</div>'
        '<div class="panel">'
        f'<p style="margin:0;line-height:1.55">{_esc(headline.summary)}</p>'
        f"{risks}"
        f'<p style="margin:10px 0 0;font-size:.72rem;color:#94a3b8">{_esc(headline.claim_boundary)}</p>'
        "</div>"
        "</section>"
    )


def _summary_cards(report: "AIBOMReport", findings: list["Finding"], policy_findings: list["Finding"]) -> str:
    crit = sum(1 for finding in findings if severity_value(finding) == "critical")
    policy_crit = sum(1 for finding in policy_findings if str(finding.severity).lower() == "critical")
    total_vulns = len(findings)
    static_count = sum(_static_inventory(agent) is not None for agent in report.agents)
    inventory_label = (
        "Inventory sources" if static_count == len(report.agents) and static_count else "Agents / inventory" if static_count else "Agents"
    )
    cred_servers = sum(1 for a in report.agents for s in a.mcp_servers if s.has_credentials)
    kev_count = sum(1 for finding in findings if finding.is_kev)

    def card(icon: str, value: str, label: str, accent: str, sub: str = "") -> str:
        sub_html = f'<div style="font-size:.68rem;color:#475569;margin-top:2px">{sub}</div>' if sub else ""
        return (
            f'<div class="stat-card" style="border-left-color:{accent}">'
            f'<div class="stat-icon">{icon}</div>'
            f'<div class="stat-value" style="color:{accent}">{_esc(value)}</div>'
            f'<div class="stat-label">{label}</div>'
            f"{sub_html}"
            f"</div>"
        )

    return (
        '<div class="stat-grid">'
        + "".join(
            [
                card("&#x1f916;", str(report.total_agents), inventory_label, "#60a5fa", f"{report.total_servers} MCP servers"),
                card("&#x1f4e6;", str(report.total_packages), "Packages", "#38bdf8", "direct + transitive"),
                card(
                    "&#x26a0;&#xfe0f;",
                    str(total_vulns),
                    "Vulnerabilities",
                    "#f87171" if total_vulns else "#34d399",
                    "in recorded inventory",
                ),
                card(
                    "&#x1f6e1;&#xfe0f;",
                    str(len(policy_findings)),
                    "Policy Findings",
                    "#f87171" if policy_findings else "#34d399",
                    "non-CVE controls",
                ),
                card("&#x1f511;", str(cred_servers), "Servers w/ Creds", "#fbbf24" if cred_servers else "#34d399", "credential exposure"),
                card(
                    "&#x1f6a8;", str(crit + policy_crit), "Critical", "#ef4444" if crit or policy_crit else "#34d399", "needs immediate fix"
                ),
                card("&#x1f9a0;", str(kev_count), "CISA KEV", "#a855f7" if kev_count else "#34d399", "actively exploited"),
            ]
        )
        + "</div>"
    )
