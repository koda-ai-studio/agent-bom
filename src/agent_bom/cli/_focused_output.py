"""Console rendering for the focused ``secrets`` and ``code`` commands."""

from __future__ import annotations

from typing import Any

from agent_bom.core.severity import severity_at_or_above


def has_finding_at_or_above(findings: Any, threshold: str = "high") -> bool:
    """Return True when focused findings should fail CI by default."""
    return any(severity_at_or_above(str(getattr(finding, "severity", "unknown")), threshold) for finding in findings)


def flow_row(finding: Any) -> str:
    cwe = f" [dim]{', '.join(finding.cwe_ids)}[/dim]" if finding.cwe_ids else ""
    return f"  {finding.file_path}:{finding.line_number}  [red]{finding.severity.upper()}[/red] {finding.title}{cwe}"


def _print_secret_coverage(result: Any, console: Any) -> None:
    for exclusion in result.exclusions:
        console.print(f"[dim]Scope exclusion: {exclusion}[/dim]")
    for warning in result.warnings:
        console.print(f"[yellow]Coverage incomplete:[/yellow] {warning}")


def _secret_negative_message(result: Any) -> str:
    if result.files_scanned:
        return "No secrets or PII detected in inspected files within the configured scope."
    return "No eligible files inspected within the configured scope."


def secret_exit_code(result: Any) -> int:
    if has_finding_at_or_above(result.findings):
        return 1
    return 2 if result.warnings else 0


def print_secret_console(report_con: Any, diagnostic_con: Any, result: Any, *, quiet: bool) -> int:
    """Render a secrets result; -q keeps the findings and the total, which are the result."""
    if not quiet:
        report_con.print(f"\n[bold]Secret scan:[/bold] {result.files_scanned} files scanned\n")
    _print_secret_coverage(result, diagnostic_con)
    if not result.findings:
        if result.warnings:
            report_con.print("No secrets or PII detected in inspected files; coverage is incomplete.")
            return 2
        report_con.print(_secret_negative_message(result))
        return 0

    for f in result.findings:
        sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(f.severity, "white")
        validation = f"  (validation: {f.validation_status})" if f.validation_status is not None else ""
        report_con.print(f"  [{sev_color}]{f.severity.upper()}[/{sev_color}]  {f.file_path}:{f.line_number}  {f.secret_type}{validation}")

    report_con.print(f"\n[bold]{result.total} findings[/bold] ({result.critical_count} critical)")
    return secret_exit_code(result)


def code_quiet_line(result: Any, ai_report: Any) -> str:
    stats = result.to_dict()["stats"]
    return (
        f"agent-bom code: {result.files_analyzed} files analyzed, {len(result.prompts)} prompt(s) "
        f"({stats['prompts_with_risks']} with risks), {len(result.guardrails)} guardrail(s), {len(result.tools)} tool(s), "
        f"{ai_report.total} AI component(s), {len(result.flow_findings)} flow finding(s)"
    )


def print_code_console(con: Any, result: Any, ai_report: Any) -> None:
    con.print(f"\n[bold]Native code analysis:[/bold] {result.files_analyzed} files analyzed\n")

    if result.prompts:
        con.print(f"[bold]System Prompts ({len(result.prompts)}):[/bold]")
        for p in result.prompts:
            risk = f" [red]⚠ {', '.join(p.risk_flags)}[/red]" if p.risk_flags else ""
            con.print(f"  {p.file_path}:{p.line_number}  [{p.prompt_type}] {p.variable_name}{risk}")
            con.print(f"    [dim]{p.text[:80]}...[/dim]")

    if result.guardrails:
        con.print(f"\n[bold]Guardrails ({len(result.guardrails)}):[/bold]")
        for g in result.guardrails:
            con.print(f"  {g.file_path}:{g.line_number}  [{g.guardrail_type}] {g.name}")

    if result.tools:
        con.print(f"\n[bold]Tool Signatures ({len(result.tools)}):[/bold]")
        for t in result.tools:
            params = ", ".join(f"{p['name']}: {p['type']}" for p in t.parameters)
            con.print(f"  {t.file_path}:{t.line_number}  {t.name}({params}) → {t.return_type}")

    _print_ai_components(con, ai_report)

    if result.flow_findings:
        con.print(f"\n[bold]Flow Findings ({len(result.flow_findings)}):[/bold]")
        for finding in result.flow_findings[:8]:
            path = " -> ".join(finding.call_path) if finding.call_path else finding.sink
            con.print(flow_row(finding))
            con.print(f"    [dim]{path}[/dim]")

    risky = result.to_dict()["stats"]["prompts_with_risks"]
    if risky:
        con.print(f"\n[red bold]{risky} prompt(s) with security risks[/red bold]")


def _print_ai_components(con: Any, ai_report: Any) -> None:
    if ai_report.total:
        con.print(f"\n[bold]AI Components ({ai_report.total} across {ai_report.files_scanned} files):[/bold]")
        for comp in ai_report.components[:12]:
            extra = " [yellow](shadow)[/yellow]" if comp.is_shadow else ""
            con.print(
                f"  {comp.file_path}:{comp.line_number}  [{comp.language}] {comp.component_type.value}  [bold]{comp.name}[/bold]{extra}"
            )
        if ai_report.total > 12:
            con.print(f"  [dim]... {ai_report.total - 12} more component finding(s)[/dim]")

    if ai_report.warnings:
        con.print("\n[yellow]Warnings:[/yellow]")
        for warning in ai_report.warnings:
            con.print(f"  [yellow]-[/yellow] {warning}")
