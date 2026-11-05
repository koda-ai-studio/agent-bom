"""Small row formatters for the compact console report."""

from __future__ import annotations

from typing import Any


def posture_grade_line(posture_grade_badge: Any, posture_headline: Any, grade: str, score: float, summary: str, *, label: str = "") -> str:
    """Grade line; an ungraded scan states why instead of showing a 0/100 score."""
    if (grade or "").upper() == "N/A":
        reason = posture_headline(summary) if summary else "not enough evidence to grade"
        return f"  [bold]Posture grade:[/bold]  {posture_grade_badge(grade)} not graded — {reason}"
    coverage = f" {label.removeprefix(grade).strip()}" if label and label != grade else ""
    line = f"  [bold]Posture grade:[/bold]  {posture_grade_badge(grade)}{coverage} {score:.0f}/100"
    return f"{line}  [dim]{posture_headline(summary)}[/dim]" if summary else line


def scorecard_grade_line(posture_grade_badge: Any, posture_headline: Any, scorecard: Any, summary: str) -> str:
    return posture_grade_line(posture_grade_badge, posture_headline, scorecard.grade, scorecard.score, summary, label=scorecard.grade_label)


def package_display(finding: Any, safe: Any) -> str:
    """``name@version`` with ``T`` for transitive and ``dev`` for development-only packages."""
    from agent_bom.output.finding_views import is_dev_dependency, is_package_direct, package_name, package_version

    transitive = "" if is_package_direct(finding) else " [dim]T[/dim]"
    dev = " [dim]dev[/dim]" if is_dev_dependency(finding) else ""
    return f"{safe(package_name(finding))}@{safe(package_version(finding))}{transitive}{dev}"


def console_group_key(finding: Any) -> tuple[str, ...] | None:
    """Key that folds repeated occurrences into one console row, or ``None`` to keep the row.

    IaC rules group by rule; MCP tool-schema rules group per server and rule,
    so one heuristic across every tool of a server reads as one row. Only the
    console groups: JSON, SARIF and the graph keep every occurrence.
    """
    evidence = finding.evidence or {}
    rule = str(evidence.get("rule_id") or finding.title or "")
    if evidence.get("iac") is True:
        return (finding.finding_type.value, rule, str(finding.severity))
    if evidence.get("category") == "schema_risk" or evidence.get("mcp_tool_rule"):
        rule = str(evidence.get("mcp_tool_rule") or evidence.get("rule_id") or "")
        return ("mcp_schema", str(evidence.get("server_name") or ""), rule.split(":")[0], str(finding.severity))
    return None
