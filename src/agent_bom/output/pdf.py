"""Executive PDF report, built from the same derivations as the HTML report.

Sections: posture (status, grade, inventory, severity mix, trend), the
executive headline, top risks with owner and SLA, a fix-first list, the
technical control evidence summary, and coverage caveats. It reuses the HTML
report's finding projection, headline and compliance scoring, so the two can
never disagree. Rendering is dependency-free (see ``pdf_canvas``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from agent_bom.core.sla import sla_status_text
from agent_bom.core.trend import trend_sentence
from agent_bom.eu_ai_act import EU_AI_ACT
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.evidence.scoring import score_compliance
from agent_bom.models import AIBOMReport, BlastRadius
from agent_bom.nist_ai_rmf import NIST_AI_RMF
from agent_bom.output.brand_tokens import REPORT_TITLE
from agent_bom.output.compact_text import GRADE_ECHO
from agent_bom.output.executive_headline import build_executive_headline
from agent_bom.output.finding_views import (
    apply_workload_runtime_evidence_for_export,
    compliance_row_dict,
    cve_findings,
    package_name,
    package_version,
    ranked_cve_findings,
    severity_value,
    workflow_status,
)
from agent_bom.output.html.sections_findings import _non_cve_findings
from agent_bom.output.html.sections_governance import _compliance_rows
from agent_bom.output.html.sections_summary import _headline_row
from agent_bom.output.pdf_canvas import CONTENT_WIDTH, MARGIN, MUTED, PAGE_HEIGHT, PdfDocument, clean, hex_color
from agent_bom.owasp import OWASP_LLM_TOP10
from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
from agent_bom.posture import compute_posture_scorecard

_ADVISORY = re.compile(r"^(CVE|GHSA|OSV|PYSEC|RUSTSEC|GO|MAL)-", re.I)
_SEVERITIES = ("critical", "high", "medium", "low", "unknown")
_SEVERITY_COLORS = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "unknown": "#64748b"}
_CLAIM_BOUNDARY = (
    "This report summarises technical scan evidence. It is not a compliance attestation, does not confirm "
    "exploitation, and covers only the inputs this scan collected."
)


@dataclass
class _Block:
    kind: str
    text: str = ""
    columns: list[tuple[str, float]] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    muted: bool = False


def _findings(report: AIBOMReport, blast_radii: list[BlastRadius] | None) -> tuple[list[Any], list[Any]]:
    findings = apply_workload_runtime_evidence_for_export(cve_findings(report, blast_radii or []))
    return findings, apply_workload_runtime_evidence_for_export(_non_cve_findings(report))


def _severity(finding: Any) -> str:
    value = str(severity_value(finding) or "").lower()
    return value if value in _SEVERITIES else "unknown"


def _status(report: AIBOMReport, findings: list[Any], policy: list[Any]) -> str:
    outcome = effective_scan_run(report).outcome
    severities = {_severity(finding) for finding in [*findings, *policy]}
    if outcome is ScanOutcome.FAILED:
        return "SCAN FAILED - results are not a security verdict"
    if outcome is ScanOutcome.PARTIAL:
        return "PARTIAL COVERAGE - a low finding count is not a clean result"
    if "critical" in severities:
        return "CRITICAL FINDINGS"
    if findings or policy:
        return "SECURITY FINDINGS"
    return "NO FINDINGS IN COLLECTED SCOPE"


def _posture_blocks(report: AIBOMReport, findings: list[Any], policy: list[Any]) -> list[_Block]:
    card = compute_posture_scorecard(report)
    grade = (
        f"Posture grade: not graded - {card.summary or 'not enough evidence to grade'}"
        if card.grade.upper() == "N/A"
        else f"Posture grade: {card.grade} ({card.score:.0f}/100) - {GRADE_ECHO.sub('', card.summary).strip()}"
    )
    counts = {severity: 0 for severity in _SEVERITIES}
    for finding in [*findings, *policy]:
        counts[_severity(finding)] += 1
    blocks = [
        _Block("heading", "Posture"),
        _Block("status", _status(report, findings, policy)),
        _Block("para", grade),
        _Block(
            "para",
            f"Inventory: {report.total_agents} agents, {report.total_servers} MCP servers, {report.total_packages} packages. "
            f"Findings: {sum(counts.values())} across all categories ({len(findings)} package vulnerabilities).",
        ),
        _Block("bar", counts=counts),
    ]
    change = getattr(report, "since_last_scan", None)
    if change:
        sentence = trend_sentence(int(change.get("new", 0)), int(change.get("resolved", 0)), partial=bool(change.get("partial")))
        blocks.append(_Block("para", f"Trend: {sentence} Previous scan: {str(change.get('previous_at') or '')[:16].replace('T', ' ')}."))
    return blocks


def _risk_blocks(report: AIBOMReport, findings: list[Any], policy: list[Any]) -> list[_Block]:
    rows_in = (_headline_row(finding, report.generated_at) for finding in [*findings, *policy])
    headline = build_executive_headline(rows_in, limit=10, include_risk_sentences=False)
    blocks = [_Block("heading", "Executive summary"), _Block("para", headline.summary)]
    if report.executive_summary:
        blocks.append(_Block("para", f"AI-generated summary: {report.executive_summary}"))
    if headline.top_risks:
        statuses = {str(f.vulnerability_id or f.id): workflow_status(f) for f in [*findings, *policy]}
        rows = [
            [
                str(index),
                risk.severity.upper(),
                f"{risk.title} ({risk.id})" if _ADVISORY.match(risk.id) and risk.id not in risk.title else risk.title,
                ", ".join(risk.affected_agents[:3]) + (f" +{len(risk.affected_agents) - 3}" if len(risk.affected_agents) > 3 else ""),
                risk.owner or "Unassigned",
                (f"{risk.sla_due_at} ({sla_status_text(risk.sla_due_at, now=report.generated_at)})" if risk.sla_due_at else "No SLA")
                + (f" / {statuses[risk.id]}" if statuses.get(risk.id) else ""),
            ]
            for index, risk in enumerate(headline.top_risks, start=1)
        ]
        blocks += [
            _Block("heading", "Top risks"),
            _Block(
                "table",
                columns=[("#", 0.04), ("Severity", 0.1), ("Risk", 0.38), ("Agents", 0.18), ("Owner", 0.15), ("SLA due / status", 0.15)],
                rows=rows,
            ),
            _Block("para", headline.claim_boundary, muted=True),
        ]
    return blocks


def _vulnerability_blocks(report: AIBOMReport, blast_radii: list[BlastRadius] | None) -> list[_Block]:
    ranked = ranked_cve_findings(report, blast_radii, limit=15)
    if not ranked:
        return []
    rows = []
    for finding in ranked:
        exposure = [*finding.exposed_credentials[:3], *([f"{len(finding.affected_agents)} agent(s)"] if finding.affected_agents else [])]
        rows.append(
            [
                str(finding.cve_id or finding.id),
                f"{package_name(finding)}@{package_version(finding)}",
                _severity(finding).upper(),
                finding.fixed_version or "No fix",
                ", ".join(exposure) or "-",
            ]
        )
    return [
        _Block("heading", "Top package vulnerabilities by blast radius"),
        _Block(
            "table",
            columns=[("Advisory", 0.2), ("Package", 0.25), ("Severity", 0.11), ("Fix", 0.14), ("Reach", 0.3)],
            rows=rows,
        ),
    ]


def _fix_blocks(findings: list[Any]) -> list[_Block]:
    best: dict[str, tuple[str, str, int]] = {}
    for finding in findings:
        if not finding.fixed_version:
            continue
        name = package_name(finding)
        current, fix, cleared = best.get(name, (package_version(finding), finding.fixed_version, 0))
        best[name] = (current, max(fix, finding.fixed_version, key=_version_key), cleared + 1)
    if not best:
        return []
    ordered = sorted(best.items(), key=lambda item: -item[1][2])[:8]
    rows = [[name, current, fix, str(cleared)] for name, (current, fix, cleared) in ordered]
    return [
        _Block("heading", "Fix first"),
        _Block("table", columns=[("Package", 0.4), ("Installed", 0.2), ("Upgrade to", 0.2), ("Clears findings", 0.2)], rows=rows),
    ]


def _version_key(value: str) -> tuple:
    try:
        return (1, Version(value))
    except InvalidVersion:
        return (0, value)


def _compliance_blocks(findings: list[Any]) -> list[_Block]:
    rows_in = [compliance_row_dict(finding) for finding in findings]
    frameworks = [
        ("OWASP Top 10 for LLM", OWASP_LLM_TOP10, "owasp_tags"),
        ("OWASP Agentic Top 10", OWASP_AGENTIC_TOP10, "owasp_agentic_tags"),
        ("NIST AI RMF", NIST_AI_RMF, "nist_ai_rmf_tags"),
        ("EU AI Act", EU_AI_ACT, "eu_ai_act_tags"),
    ]
    counts = [(name, _compliance_rows(rows_in, catalog, field_name)[1]) for name, catalog, field_name in frameworks]
    verdict = score_compliance(
        passed=sum(c["pass"] for _, c in counts), warned=sum(c["warning"] for _, c in counts), failed=sum(c["fail"] for _, c in counts)
    )
    table = [[name, str(c["fail"]), str(c["warning"]), str(c["pass"]), str(c["not_evaluated"])] for name, c in counts]
    overall = (
        f"Overall: {verdict.status} over {verdict.evaluated} evaluated controls."
        if verdict.is_evaluated
        else "Overall: not evaluated - no package finding mapped to these controls, so posture is unknown, not compliant."
    )
    return [
        _Block("heading", "Technical control evidence"),
        _Block("para", overall),
        _Block(
            "table",
            columns=[("Framework", 0.4), ("Fail", 0.15), ("Warning", 0.15), ("Pass", 0.15), ("Not evaluated", 0.15)],
            rows=table,
        ),
        _Block("para", "Control mappings are investigation context for package vulnerabilities, not audit certification.", muted=True),
    ]


def _coverage_blocks(report: AIBOMReport) -> list[_Block]:
    run = effective_scan_run(report)
    blocks = [_Block("heading", "Coverage and caveats"), _Block("para", f"Scan outcome: {run.outcome.value}.")]
    for issue in list(run.issues)[:8]:
        blocks.append(_Block("para", f"- {issue.source}: {issue.message}"))
    warnings = list(getattr(report, "coverage_warnings", None) or [])
    if warnings:
        blocks.append(_Block("para", f"{len(warnings)} coverage warning(s) recorded; see the JSON report for each one."))
    freshness = getattr(report, "vuln_data_freshness", None)
    if isinstance(freshness, dict) and freshness.get("summary"):
        blocks.append(_Block("para", f"Vulnerability data: {freshness['summary']}"))
    blocks.append(_Block("para", _CLAIM_BOUNDARY, muted=True))
    return blocks


def _blocks(report: AIBOMReport, blast_radii: list[BlastRadius] | None) -> list[_Block]:
    findings, policy = _findings(report, blast_radii)
    meta = (
        f"Generated {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')} | agent-bom {report.tool_version or 'unknown'} | "
        f"scan {report.scan_id or 'n/a'}"
    )
    if report.scan_sources:
        meta += f" | sources: {', '.join(report.scan_sources)}"
    return [
        _Block("title", REPORT_TITLE),
        _Block("meta", meta),
        *_posture_blocks(report, findings, policy),
        *_risk_blocks(report, findings, policy),
        *_vulnerability_blocks(report, blast_radii),
        *_fix_blocks(findings),
        *_compliance_blocks(findings),
        *_coverage_blocks(report),
    ]


def _build_report_lines(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> list[str]:
    """Every text the PDF will contain, in order (used by redaction contracts)."""
    lines: list[str] = []
    for block in _blocks(report, blast_radii):
        if block.text:
            lines.append(clean(block.text))
        lines.extend(clean(" | ".join(row)) for row in block.rows)
    return lines


def _draw_bar(doc: PdfDocument, counts: dict[str, int]) -> None:
    total = sum(counts.values())
    doc.ensure(34)
    if not total:
        doc.paragraph("No findings in the collected scope.", color=MUTED)
        return
    x: float = MARGIN
    top = doc.y - 12
    for severity in _SEVERITIES:
        width = CONTENT_WIDTH * counts[severity] / total
        if width:
            doc.rect(x, top, width, 10, hex_color(_SEVERITY_COLORS[severity]))
            x += width
    legend = "   ".join(f"{severity.capitalize()} {counts[severity]}" for severity in _SEVERITIES if counts[severity])
    doc.text(MARGIN, top - 12, legend, size=8, color=MUTED)
    doc.y = top - 22


def _render(blocks: list[_Block], footer: str) -> bytes:
    doc = PdfDocument(footer=footer)
    for block in blocks:
        if block.kind == "title":
            doc.rect(0, PAGE_HEIGHT - 70, 612, 70, hex_color("#0f172a"))
            doc.text(MARGIN, PAGE_HEIGHT - 42, block.text, size=18, bold=True, color=(1, 1, 1))
            doc.y = PAGE_HEIGHT - 82
        elif block.kind == "meta":
            doc.paragraph(block.text, size=8, color=MUTED)
        elif block.kind == "heading":
            doc.heading(block.text)
        elif block.kind == "status":
            doc.paragraph(block.text, size=12, bold=True)
        elif block.kind == "bar":
            _draw_bar(doc, block.counts)
        elif block.kind == "table":
            doc.table(block.columns, block.rows)
        else:
            doc.paragraph(block.text, color=MUTED if block.muted else (0.06, 0.09, 0.16), size=8 if block.muted else 9.5)
    return doc.build()


def to_pdf(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> bytes:
    """Render the executive PDF report to bytes."""
    return _render(_blocks(report, blast_radii), footer=f"{REPORT_TITLE} | {report.generated_at.strftime('%Y-%m-%d')}")


def export_pdf(report: AIBOMReport, output_path: str, blast_radii: list[BlastRadius] | None = None) -> None:
    """Write the rendered PDF report to disk."""
    Path(output_path).write_bytes(to_pdf(report, blast_radii))
