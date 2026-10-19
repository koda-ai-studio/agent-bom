"""Output html sections governance helpers."""

from __future__ import annotations

from collections.abc import Callable

from agent_bom.core.severity import (
    SEVERITY_THRESHOLD_LABELS,
    severity_worst_first_rank,
)
from agent_bom.finding import Finding
from agent_bom.models import AIBOMReport
from agent_bom.output.cis_posture import (
    ERROR,
    EVALUATED_STATUSES,
    INCOMPLETE,
    NOT_EVALUATED,
    PASS,
    cis_pass_rate,
    cis_verdict,
)
from agent_bom.output.finding_views import (
    compliance_row_dict,
)
from agent_bom.output.html._common import (
    _SEV_COLOR,
    _esc,
    _sev_badge,
)
from agent_bom.output.html.sections_findings import (
    _CIS_CLOUD_LABELS as _CIS_CLOUD_LABELS,
)
from agent_bom.output.technique_evidence import html_atlas_sources

_CIS_VERDICT_COLOR = {
    NOT_EVALUATED: "#6b7280",
    ERROR: "#dc2626",
    INCOMPLETE: "#d97706",
    PASS: "#16a34a",
}


def _cis_evidence_html(check: dict) -> str:
    """Affected-resource evidence cell: resource IDs when present, else text."""
    resources = check.get("resource_ids") or []
    if resources:
        chips = "".join(
            f'<span style="display:inline-block;padding:1px 7px;margin:1px 3px 1px 0;border-radius:4px;'
            f"background:#0f172a;color:#cbd5e1;font-size:.66rem;font-family:monospace;"
            f'word-break:break-all">{_esc(r)}</span>'
            for r in resources[:6]
        )
        if len(resources) > 6:
            chips += f'<span style="color:#475569;font-size:.66rem">+{len(resources) - 6} more</span>'
        return chips
    evidence = str(check.get("evidence") or "").strip()
    if evidence:
        return f'<span style="color:#94a3b8;font-size:.72rem">{_esc(evidence)}</span>'
    return '<span style="color:#475569;font-size:.7rem">&mdash;</span>'


def _cis_benchmark_section(report: "AIBOMReport") -> str:
    """Build the CIS benchmark posture section (issue #665).

    Renders one sub-panel per cloud with a CIS benchmark bundle. Each failed
    or unevaluable check surfaces its structured remediation dict (``fix_cli``,
    ``fix_console``, ``priority``, ``guardrails``, human-review flag).
    Returns an empty string when no CIS data is present.
    """

    def _sort_key(c: dict) -> tuple[int, int, str]:
        rem = c.get("remediation") or {}
        priority = rem.get("priority", 3)
        if not isinstance(priority, int):
            priority = 3
        return (severity_worst_first_rank(c.get("severity")), priority, str(c.get("check_id") or ""))

    from agent_bom.cloud.cis_remediation import fail_closed_cis_bundle

    panels: list[str] = []
    for idx, (cloud_key, (label, attr)) in enumerate(_CIS_CLOUD_LABELS.items()):
        bundle = getattr(report, attr, None)
        if not bundle:
            continue
        if cloud_key in {"aws", "azure", "gcp", "snowflake"}:
            bundle = fail_closed_cis_bundle(bundle, cloud=cloud_key)
        checks = bundle.get("checks") or []
        if not checks:
            continue
        header, actionable, verdict_text, sev_counts = _cis_panel_header(bundle, checks, label, _sort_key)

        if not actionable:
            body = (
                "No control produced a pass or a fail &mdash; nothing was evaluated."
                if verdict_text == NOT_EVALUATED
                else "&#x2705; No failed security checks."
            )
            panels.append(
                f'<div class="panel" style="margin-bottom:16px">{header}<div class="empty-state" style="margin-top:12px">{body}</div></div>'
            )
            continue

        panel_id = f"cis-{_esc(cloud_key)}"
        filter_btns = _cis_filter_buttons(panel_id, sev_counts)

        rows = _cis_action_rows(actionable, _sort_key)

        table_html = (
            f'<div class="table-wrap"><table class="data-table sortable" id="{panel_id}">'
            + "<thead><tr>"
            + "".join(
                f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>'
                for i, h in enumerate(["Severity", "Check", "Title", "Priority", "Evidence", "Guardrails", "Remediation"])
            )
            + "</tr></thead>"
            + f"<tbody>{''.join(rows)}</tbody></table></div>"
        )

        panels.append(f'<div class="panel" style="margin-bottom:16px">{header}{filter_btns}{table_html}</div>')

    if not panels:
        return ""

    filter_script = (
        "<script>document.querySelectorAll('.cis-filter').forEach(function(bar){"
        "bar.querySelectorAll('.cis-filter-btn').forEach(function(btn){"
        "btn.addEventListener('click',function(){"
        "var tbl=document.getElementById(bar.getAttribute('data-target'));if(!tbl)return;"
        "var sev=btn.getAttribute('data-sev');"
        "tbl.querySelectorAll('tbody tr.cis-row').forEach(function(r){"
        "r.style.display=(sev==='all'||r.getAttribute('data-sev')===sev)?'':'none';});"
        "bar.querySelectorAll('.cis-filter-btn').forEach(function(b){b.style.color='#94a3b8';});"
        "btn.style.color='#f1f5f9';});});});</script>"
    )

    return (
        '<section id="cisbenchmarks"><div class="sec-title">&#x1f6e1;&#xfe0f; Cloud Security Posture</div>'
        + "".join(panels)
        + filter_script
        + "</section>"
    )


def _trust_assessment_section(report: "AIBOMReport") -> str:
    """Build the trust assessment section if data is available."""
    data = getattr(report, "trust_assessment_data", None)
    if not data:
        return ""

    skill_name = _esc(data.get("skill_name", ""))
    source_file = _esc(data.get("source_file", ""))
    verdict = data.get("verdict", "benign").upper()
    content_verdict = data.get("content_verdict", data.get("verdict", "benign")).upper()
    provenance_verdict = data.get("provenance_verdict", "unverified").upper()
    recommendation = data.get("overall_recommendation") or data.get("review_verdict", "review")
    confidence = data.get("confidence", "low")
    categories = data.get("categories", [])
    recommendations = data.get("recommendations", [])

    verdict_colors = {"BENIGN": "#16a34a", "SUSPICIOUS": "#d97706", "MALICIOUS": "#dc2626"}
    verdict_color = verdict_colors.get(verdict, "#6b7280")

    cat_rows = _trust_category_rows(categories)

    verdict_badge = (
        f'<span style="background:{verdict_color};color:#fff;padding:4px 14px;border-radius:6px;'
        f'font-size:.82rem;font-weight:700;letter-spacing:.04em">{verdict}</span>'
        f'<span style="color:#64748b;font-size:.78rem;margin-left:8px">({confidence} confidence)</span>'
    )
    axis_html = (
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">'
        f'<span style="background:#0f766e;color:#fff;padding:4px 10px;border-radius:6px;font-size:.76rem">'
        f"content: {_esc(content_verdict)}</span>"
        f'<span style="background:#4338ca;color:#fff;padding:4px 10px;border-radius:6px;font-size:.76rem">'
        f"provenance: {_esc(provenance_verdict)}</span>"
        f'<span style="background:#475569;color:#fff;padding:4px 10px;border-radius:6px;font-size:.76rem">'
        f"recommendation: {_esc(str(recommendation).upper())}</span>"
        "</div>"
    )

    title_suffix = f" &mdash; {skill_name}" if skill_name else ""
    source_note = (
        f'<div style="font-size:.72rem;color:#475569;margin-bottom:12px">Source: <code>{source_file}</code></div>' if source_file else ""
    )

    rec_html = ""
    if recommendations:
        rec_items = "".join(f'<li style="color:#4ade80;font-size:.78rem;margin-bottom:4px">{_esc(r)}</li>' for r in recommendations)
        rec_html = f'<ul style="list-style:none;padding:0;margin-top:16px">{rec_items}</ul>'

    headers = ["", "Category", "Level", "Summary"]
    table_html = (
        '<div class="table-wrap"><table class="data-table">'
        + "<thead><tr>"
        + "".join(f"<th>{h}</th>" for h in headers)
        + "</tr></thead>"
        + f"<tbody>{''.join(cat_rows)}</tbody></table></div>"
    )

    return (
        f'<section id="trust">'
        f'<div class="sec-title">&#x1f50d; Trust Assessment{title_suffix}</div>'
        f'<div class="panel">'
        f"{source_note}"
        f'<div style="margin-bottom:16px">{verdict_badge}</div>'
        f"{axis_html}"
        f"{table_html}"
        f"{rec_html}"
        f"</div></section>"
    )


def _enforcement_section(report: "AIBOMReport") -> str:
    """Build the enforcement findings section if data is available."""
    data = getattr(report, "enforcement_data", None)
    if not data:
        return ""

    findings = data.get("findings", [])
    passed = data.get("passed", True)
    servers_checked = data.get("servers_checked", 0)
    tools_checked = data.get("tools_checked", 0)
    critical_count = data.get("critical_count", 0)
    high_count = data.get("high_count", 0)

    status_color = "#16a34a" if passed else "#dc2626"
    status_text = "PASSED" if passed else "FAILED"

    stats_html = (
        f'<div style="display:flex;gap:24px;margin-bottom:16px;font-size:.82rem;color:#94a3b8">'
        f'<span>Status: <strong style="color:{status_color}">{status_text}</strong></span>'
        f"<span>Servers checked: <strong>{servers_checked}</strong></span>"
        f"<span>Tools checked: <strong>{tools_checked}</strong></span>"
        f'<span>Critical: <strong style="color:#dc2626">{critical_count}</strong></span>'
        f'<span>High: <strong style="color:#ea580c">{high_count}</strong></span>'
        f"</div>"
    )

    if not findings:
        return (
            f'<section id="enforcement">'
            f'<div class="sec-title">&#x1f6a8; Enforcement</div>'
            f'<div class="panel">{stats_html}'
            f'<div class="empty-state">&#x2705; No enforcement findings — all checks passed.</div>'
            f"</div></section>"
        )

    rows = []
    for f in findings:
        sev = f.get("severity", "low")
        rows.append(
            f"<tr>"
            f"<td>{_sev_badge(sev)}</td>"
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(f.get("category", ""))}</code></td>'
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{_esc(f.get("server_name", ""))}</td>'
            f'<td style="font-size:.78rem;color:#94a3b8">{_esc(f.get("tool_name", "") or "—")}</td>'
            f'<td style="font-size:.78rem;color:#94a3b8;max-width:350px">{_esc(f.get("reason", ""))}</td>'
            f'<td style="font-size:.75rem;color:#4ade80">{_esc(f.get("recommendation", ""))}</td>'
            f"</tr>"
        )

    headers = ["Severity", "Category", "Server", "Tool", "Reason", "Recommendation"]
    table_html = (
        '<div class="table-wrap"><table class="data-table sortable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + "</tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
    )

    return (
        f'<section id="enforcement">'
        f'<div class="sec-title">&#x1f6a8; Enforcement'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(findings)}</sup></div>'
        f'<div class="panel">{stats_html}{table_html}</div>'
        f"</section>"
    )


# ─── Compliance section ──────────────────────────────────────────────────────

_BADGE_STYLE = "color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem"

_STATUS_BADGE = {
    "pass": f'<span style="background:#16a34a;{_BADGE_STYLE}">PASS</span>',
    "warning": f'<span style="background:#d97706;{_BADGE_STYLE}">WARN</span>',
    "fail": f'<span style="background:#dc2626;{_BADGE_STYLE}">FAIL</span>',
    # A control with no mapped finding was NEVER evaluated. Rendering it green
    # turned a clean scan into hundreds of PASS badges and a "100.0% PASS"
    # headline in the document customers hand to auditors.
    "not_evaluated": f'<span style="background:#64748b;{_BADGE_STYLE}">NOT EVALUATED</span>',
    "no_data": f'<span style="background:#64748b;{_BADGE_STYLE}">NOT EVALUATED</span>',
    "applicable": f'<span style="background:#475569;{_BADGE_STYLE}">APPLICABLE</span>',
    "not_applicable": f'<span style="background:#64748b;{_BADGE_STYLE}">NOT APPLICABLE</span>',
}


def _compliance_section(findings: list["Finding"]) -> str:
    """Build OWASP/ATLAS/ATT&CK/NIST compliance tables from unified CVE findings."""
    try:
        from agent_bom.atlas import ATLAS_TECHNIQUES
        from agent_bom.eu_ai_act import EU_AI_ACT
        from agent_bom.mitre_attack import ATTACK_TECHNIQUES
        from agent_bom.nist_ai_rmf import NIST_AI_RMF
        from agent_bom.owasp import OWASP_LLM_TOP10
        from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    except ImportError:
        return ""

    br_dicts = [compliance_row_dict(finding) for finding in findings]

    owasp_rows, owasp_counts = _compliance_rows(br_dicts, OWASP_LLM_TOP10, "owasp_tags")
    atlas_rows, atlas_counts = _compliance_rows(br_dicts, ATLAS_TECHNIQUES, "atlas_tags", overlay=True)
    attack_rows, attack_counts = _compliance_rows(br_dicts, dict(ATTACK_TECHNIQUES), "attack_tags", overlay=True)
    nist_rows, nist_counts = _compliance_rows(br_dicts, NIST_AI_RMF, "nist_ai_rmf_tags")
    agentic_rows, agentic_counts = _compliance_rows(br_dicts, OWASP_AGENTIC_TOP10, "owasp_agentic_tags")
    eu_rows, eu_counts = _compliance_rows(br_dicts, EU_AI_ACT, "eu_ai_act_tags")

    # ATT&CK and ATLAS are absent: applicability overlays have no pass rate,
    # and cannot enter the denominator for control implementation evidence.
    scored_counts = [owasp_counts, nist_counts, agentic_counts, eu_counts]

    # Same scorer as /v1/compliance, the per-framework route, the MCP tool and
    # the evidence bundle — one derivation of status + score. None of these
    # catalogues carry detective controls, so every evaluated control is
    # substantive.
    from agent_bom.evidence.scoring import score_compliance

    verdict = score_compliance(
        passed=sum(c["pass"] for c in scored_counts),
        warned=sum(c["warning"] for c in scored_counts),
        failed=sum(c["fail"] for c in scored_counts),
    )
    score = verdict.score
    overall_badge = _STATUS_BADGE[verdict.status]
    evaluated_note = (
        f"{verdict.evaluated} of {sum(sum(c.values()) for c in scored_counts)} controls evaluated"
        if verdict.is_evaluated
        else "no control was evaluated"
    )

    return html_atlas_sources(findings) + (
        f'<section id="compliance">'
        f'<div class="sec-title">&#x1f6e1;&#xfe0f; Compliance Posture'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">'
        f"Score: {score}% {overall_badge} &middot; {_esc(evaluated_note)}</sup></div>"
        f'<div class="panel">'
        f"{_compliance_table('OWASP LLM Top 10', owasp_rows, owasp_counts)}"
        f"{_compliance_table('OWASP Agentic Top 10', agentic_rows, agentic_counts)}"
        f"{_compliance_table('MITRE ATT&CK Enterprise', attack_rows, attack_counts, overlay=True)}"
        f"{_compliance_table('MITRE ATLAS (AI/ML)', atlas_rows, atlas_counts, overlay=True)}"
        f"{_compliance_table('NIST AI RMF', nist_rows, nist_counts)}"
        f"{_compliance_table('EU AI Act', eu_rows, eu_counts)}"
        f"</div></section>"
    )


def _compliance_rows(br_dicts: list[dict], catalog: dict[str, str], tag_field: str, *, overlay: bool = False) -> tuple[str, dict[str, int]]:
    """Render one framework table and its status counts.

    These catalogues are all corrective/preventive — attested by the ABSENCE
    of an open weakness — so a control with no mapped finding is
    ``not_evaluated``, never a pass. Absence of a CVE is not proof a control
    is implemented; scoring it as one produced "100.0% PASS" over an estate
    nothing had been measured on. Mirrors evidence/control_modes.py and the
    /v1/compliance semantics.

    ``overlay`` marks an APPLICABILITY framework (MITRE ATT&CK): its
    techniques describe adversary behaviour the estate is exposed to, and
    can never "pass". It reports applicable / not_applicable and is excluded
    from the score entirely.
    """
    rows = []
    counts = {"pass": 0, "warning": 0, "fail": 0, "not_evaluated": 0, "applicable": 0, "not_applicable": 0}
    for code, name in sorted(catalog.items()):
        findings = sum(1 for b in br_dicts if code in b.get(tag_field, []))
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for b in br_dicts:
            if code in b.get(tag_field, []):
                s = b.get("severity", "").lower()
                if s in sev_counts:
                    sev_counts[s] += 1
        if overlay:
            status = "applicable" if findings else "not_applicable"
        elif findings == 0:
            status = "not_evaluated"
        elif sev_counts["critical"] > 0 or sev_counts["high"] > 0:
            status = "fail"
        else:
            status = "warning"
        counts[status] += 1
        badge = _STATUS_BADGE[status]
        rows.append(
            f"<tr><td><code>{_esc(code)}</code></td><td>{_esc(name)}</td>"
            f"<td style='text-align:center'>{findings}</td><td style='text-align:center'>{badge}</td></tr>"
        )
    return "\n".join(rows), counts


def _compliance_table(title: str, rows: str, counts: dict[str, int], *, overlay: bool = False) -> str:
    """Header caption states what was EVALUATED, never `n/total pass`.

    `(p/total pass)` counted never-evaluated controls in the denominator, so
    a framework nothing touched read as "0/65 pass" — indistinguishable from
    65 real failures.
    """
    if overlay:
        caption = f"{counts['applicable']} applicable / {counts['applicable'] + counts['not_applicable']} techniques"
    else:
        evaluated = counts["pass"] + counts["warning"] + counts["fail"]
        caption = f"{counts['pass']}/{evaluated} pass of {evaluated} evaluated" if evaluated else "not evaluated"
    return (
        f'<details style="margin-bottom:12px" {"open" if counts["fail"] > 0 else ""}>'
        f'<summary style="cursor:pointer;font-weight:600;padding:6px 0">'
        f'{title} <span style="font-size:.8rem;color:#94a3b8">({caption})</span></summary>'
        f'<table class="vtable" style="margin-top:8px"><thead><tr>'
        f"<th>Code</th><th>Control</th><th>Findings</th><th>Status</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></details>"
    )


def _cis_action_rows(actionable: list[dict], sort_key: Callable) -> list[str]:
    rows = []
    for check in sorted(actionable, key=sort_key):
        sev = (check.get("severity") or "").lower()
        rem = check.get("remediation") or {}
        fix_cli = rem.get("fix_cli")
        fix_console = rem.get("fix_console") or ""
        effort = rem.get("effort") or "manual"
        priority = rem.get("priority", 3)
        guardrails = rem.get("guardrails") or []
        guard_html = "".join(
            f'<span style="display:inline-block;padding:1px 7px;margin:1px 3px 1px 0;border-radius:4px;background:#1e293b;color:#94a3b8;font-size:.65rem;font-family:monospace">{_esc(g)}</span>'
            for g in guardrails[:5]
        )
        if len(guardrails) > 5:
            guard_html += f'<span style="color:#475569;font-size:.65rem">+{len(guardrails) - 5}</span>'
        review_badge = (
            '<span style="color:#eab308;font-size:.7rem;margin-left:6px">&#8634; review</span>' if rem.get("requires_human_review") else ""
        )

        fix_cell = ""
        if fix_cli:
            fix_cell = f'<code style="color:#67e8f9;font-size:.72rem;white-space:pre-wrap;word-break:break-all">{_esc(fix_cli)}</code>'
        elif fix_console:
            fix_cell = f'<span style="color:#94a3b8;font-size:.72rem">&rarr; {_esc(fix_console)}</span>'
        elif check.get("recommendation"):
            fix_cell = f'<span style="color:#94a3b8;font-size:.72rem">{_esc(check.get("recommendation"))}</span>'

        docs_link = ""
        docs = rem.get("docs") or ""
        if docs:
            docs_link = f' &middot; <a href="{_esc(docs)}" target="_blank" rel="noopener" style="font-size:.7rem">docs</a>'

        rows.append(
            f'<tr class="cis-row" data-sev="{_esc(sev)}">'
            f"<td>{_sev_badge(sev)}</td>"
            f'<td style="font-family:monospace;color:#f1f5f9;font-weight:600">{_esc(check.get("check_id", ""))}</td>'
            f'<td style="color:#e2e8f0;font-size:.82rem">{_esc(check.get("title", ""))}{review_badge}</td>'
            f'<td style="color:#94a3b8;font-size:.75rem">P{priority} &middot; {_esc(effort)}</td>'
            f"<td>{_cis_evidence_html(check)}</td>"
            f"<td>{guard_html}</td>"
            f"<td>{fix_cell}{docs_link}</td>"
            "</tr>"
        )
    return rows


def _cis_panel_header(bundle: dict, checks: list[dict], label: str, sort_key: Callable) -> tuple[str, list[dict], str, dict[str, int]]:
    failed = [c for c in checks if c.get("status") == "fail"]
    errored = [c for c in checks if c.get("status") == "error"]
    actionable = failed + errored
    evaluated = [c for c in checks if c.get("status") in EVALUATED_STATUSES]
    passed_n = bundle.get("passed", sum(1 for c in checks if c.get("status") == "pass"))
    pass_rate = cis_pass_rate(bundle, checks)
    band_color = "#16a34a" if pass_rate >= 90 else "#eab308" if pass_rate >= 70 else "#ef4444"

    # Verdict + per-severity failed counts for the summary header.
    sev_counts = {s: sum(1 for c in failed if (c.get("severity") or "").lower() == s) for s in SEVERITY_THRESHOLD_LABELS}
    verdict_text = cis_verdict(checks)
    verdict_color = _CIS_VERDICT_COLOR.get(verdict_text) or _SEV_COLOR.get(verdict_text.split()[0].lower(), "#ef4444")
    if verdict_text == NOT_EVALUATED:
        band_color = "#6b7280"

    top = sorted(actionable, key=sort_key)[:3]
    top_html = ""
    if top:
        chips = "".join(
            f'<code style="background:#1e293b;color:#f1f5f9;padding:1px 6px;border-radius:4px;'
            f'margin-right:5px;font-size:.7rem">{_esc(c.get("check_id", ""))}</code>'
            for c in top
        )
        top_html = f'<div style="color:#64748b;font-size:.74rem;margin-top:6px">top risks: {chips}</div>'

    counts_html = " ".join(
        f'<span style="color:{_SEV_COLOR.get(s, "#6b7280")};font-size:.72rem;font-weight:700">{n} {s[0].upper()}</span>'
        for s, n in sev_counts.items()
        if n
    )
    pass_html = (
        f'<div style="color:{band_color};font-weight:700">{pass_rate:.0f}% pass</div>'
        if evaluated
        else '<div style="color:#94a3b8;font-weight:700">pass rate unavailable</div>'
    )

    header = (
        f'<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;margin-bottom:4px">'
        f'<div style="font-weight:700;color:#f1f5f9;font-size:.95rem">{_esc(label)}</div>'
        f'<span style="background:{verdict_color};color:#fff;padding:2px 9px;border-radius:4px;'
        f'font-size:.7rem;font-weight:700;letter-spacing:.04em">{verdict_text}</span>'
        f"{pass_html}"
        f'<div style="color:#64748b;font-size:.78rem">'
        f"{passed_n}/{len(evaluated)} evaluated &middot; "
        f'<strong style="color:#f97316">{len(failed)} failed</strong>'
        f' &middot; <strong style="color:#d97706">{len(errored)} unevaluable</strong>'
        f"</div>"
        f'<div style="display:flex;gap:10px">{counts_html}</div>'
        f"</div>"
        f"{top_html}"
    )
    return header, actionable, verdict_text, sev_counts


def _trust_category_rows(categories: list[dict]) -> list[str]:
    level_icons = {"pass": "&#x2713;", "info": "&#x2139;", "warn": "&#x26a0;", "fail": "&#x2717;"}
    level_colors = {"pass": "#16a34a", "info": "#60a5fa", "warn": "#d97706", "fail": "#dc2626"}

    cat_rows = []
    for cat in categories:
        level = cat.get("level", "pass")
        icon = level_icons.get(level, "?")
        color = level_colors.get(level, "#6b7280")
        cat_rows.append(
            f"<tr>"
            f'<td style="text-align:center;color:{color};font-size:1.1rem">{icon}</td>'
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{_esc(cat.get("name", ""))}</td>'
            f"<td>{_sev_badge(level)}</td>"
            f'<td style="font-size:.78rem;color:#94a3b8">{_esc(cat.get("summary", ""))}</td>'
            f"</tr>"
        )
    return cat_rows


def _cis_filter_buttons(panel_id: str, sev_counts: dict[str, int]) -> str:
    # Severity filter buttons (client-side, per panel).
    filter_btns = (
        f'<div class="cis-filter" data-target="{panel_id}" style="margin:10px 0 4px">'
        + "".join(
            f'<button type="button" class="cis-filter-btn" data-sev="{sev}" '
            f'style="background:#1e293b;color:#94a3b8;border:1px solid #334155;border-radius:4px;'
            f'padding:2px 9px;margin-right:6px;font-size:.7rem;cursor:pointer">{lbl}</button>'
            for sev, lbl in (
                ("all", "All"),
                ("critical", "Critical"),
                ("high", "High"),
                ("medium", "Medium"),
                ("low", "Low"),
            )
            if sev == "all" or sev_counts.get(sev)
        )
        + "</div>"
    )

    return filter_btns
