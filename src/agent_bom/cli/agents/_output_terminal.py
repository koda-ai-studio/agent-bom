"""Terminal and pipe emission for a completed scan report."""

from __future__ import annotations

import json
import sys
from typing import Any

import click
from rich.panel import Panel

from agent_bom.cli._agent_mode import dumps_envelope, success_envelope
from agent_bom.cli._terminal_sections import print_scan_next_steps, print_section_divider
from agent_bom.cli.agents._cloud import render_cis_findings_from_context
from agent_bom.cli.agents._context import ScanContext
from agent_bom.output import (
    print_agent_tree,
    print_attack_flow_tree,
    print_blast_radius,
    print_compact_agents,
    print_compact_blast_radius,
    print_compact_cis_posture,
    print_compact_export_hint,
    print_compact_graph_findings,
    print_compact_remediation,
    print_compact_summary,
    print_export_hint,
    print_posture_summary,
    print_remediation_plan,
    print_scan_performance_summary,
    print_severity_chart,
    print_summary,
    print_threat_frameworks,
    to_csv,
    to_cyclonedx,
    to_junit,
    to_markdown,
    to_prometheus,
    to_redacted_json,
    to_sarif,
    to_spdx,
    to_spdx2,
)
from agent_bom.output.console_compliance_gate import print_compact_compliance_section
from agent_bom.output.console_kubernetes import print_kubernetes_workloads
from agent_bom.output.json_fmt import write_redacted_json


def _emit_stdout_report(
    agent_mode: Any,
    agent_mode_full: Any,
    agent_token_budget: Any,
    blast_radii: Any,
    ctx: ScanContext,
    exclude_unfixable: Any,
    mermaid_mode: Any,
    offline_html: Any,
    output: Any,
    output_format: Any,
    report: Any,
) -> None:
    if _emit_stdout_standard(blast_radii, exclude_unfixable, offline_html, output_format, report):
        pass
    elif output_format == "graph":
        from agent_bom.output.graph import build_graph_elements

        elements = build_graph_elements(report, blast_radii)
        sys.stdout.write(json.dumps({"elements": elements, "format": "cytoscape"}, indent=2))
    elif output_format == "mermaid":
        if mermaid_mode == "attack-flow":
            from agent_bom.output.mermaid import to_mermaid

            sys.stdout.write(to_mermaid(report, blast_radii))
        elif mermaid_mode == "lifecycle":
            from agent_bom.output.mermaid import to_mermaid_lifecycle

            sys.stdout.write(to_mermaid_lifecycle(report, blast_radii))
        else:
            from agent_bom.output.mermaid import to_mermaid_supply_chain

            sys.stdout.write(to_mermaid_supply_chain(report))
    elif output_format == "svg":
        from agent_bom.output.svg import to_svg

        sys.stdout.write(to_svg(report, blast_radii))
    elif output_format == "junit":
        sys.stdout.write(to_junit(report, blast_radii))
    elif output_format == "csv":
        sys.stdout.write(to_csv(report, blast_radii))
    elif output_format == "parquet":
        click.echo("Error: --format parquet requires --output/-o (binary Parquet)", err=True)
        sys.exit(2)
    elif output_format == "markdown":
        sys.stdout.write(to_markdown(report, blast_radii))
    elif output_format == "graph-html":
        click.echo("Error: --format graph-html requires --output/-o (cannot write HTML to stdout)", err=True)
        sys.exit(2)
    elif agent_mode:
        payload = success_envelope(
            command="agents",
            report_json=to_redacted_json(report, report_json=ctx.report_json),
            exit_code=ctx.exit_code,
            token_budget=agent_token_budget,
            full=agent_mode_full,
            output_path=output if isinstance(output, str) else None,
        )
        click.echo(dumps_envelope(payload), nl=False)
    else:
        write_redacted_json(report, sys.stdout, report_json=ctx.report_json, newline=False)
    sys.stdout.write("\n")


def _emit_skill_analysis(_skill_audit_obj: Any, con: Any) -> None:
    if _skill_audit_obj and _skill_audit_obj.ai_skill_summary:
        sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim", "safe": "green"}
        risk = _skill_audit_obj.ai_overall_risk_level or "unknown"
        risk_style = sev_colors.get(risk, "white")
        con.print(f"\n[bold]Skill File AI Analysis[/bold]  [{risk_style}]\\[{risk.upper()}][/{risk_style}]")
        con.print(Panel.fit(_skill_audit_obj.ai_skill_summary, border_style="cyan"))

        # Show AI-adjusted findings
        adjusted = [sk_f for sk_f in _skill_audit_obj.findings if sk_f.ai_adjusted_severity]
        if adjusted:
            for sk_f in adjusted:
                if sk_f.ai_adjusted_severity == "false_positive":
                    con.print(f"  [green]✓ FP[/green] {sk_f.title}")
                    con.print(f"    [dim]{sk_f.ai_analysis}[/dim]")
                else:
                    con.print(f"  [yellow]↕ ADJ[/yellow] {sk_f.title}: {sk_f.severity} → {sk_f.ai_adjusted_severity}")
                    if sk_f.ai_analysis:
                        con.print(f"    [dim]{sk_f.ai_analysis}[/dim]")

        # Show AI-detected new findings
        ai_detected = [sk_f for sk_f in _skill_audit_obj.findings if sk_f.context == "ai_analysis"]
        if ai_detected:
            con.print(f"\n  [bold yellow]AI-Detected Threats ({len(ai_detected)})[/bold yellow]")
            for sk_f in ai_detected:
                style = sev_colors.get(sk_f.severity, "white")
                con.print(f"    [{style}]\\[{sk_f.severity.upper()}][/{style}] {sk_f.title}")
                con.print(f"      [dim]{sk_f.detail}[/dim]")
                if sk_f.recommendation:
                    con.print(f"      [green]→ {sk_f.recommendation}[/green]")


def _emit_console_report(
    compact_page: Any, con: Any, ctx: ScanContext, fixable_only: Any, kwargs: Any, no_tree: Any, quiet: Any, report: Any, verbose: Any
) -> None:
    _skill_audit_obj = ctx._skill_audit_obj
    if verbose:
        # Full output (--verbose)
        print_section_divider(con, "Report")
        print_summary(report)
        print_scan_performance_summary(report)
        print_posture_summary(report)
        if not no_tree:
            print_agent_tree(report)
        print_kubernetes_workloads(con, report.kubernetes_inventory_data)
        print_severity_chart(report)
        print_blast_radius(report, fixable_only=fixable_only)
        print_compact_graph_findings(report, limit=100)
        if not no_tree:
            print_attack_flow_tree(report)
        print_threat_frameworks(report)
    else:
        # Compact output (default) — verdict-led posture summary.
        print_section_divider(con, "Summary")
        print_compact_summary(report, verbose=verbose)
        print_compact_agents(report)
        print_kubernetes_workloads(con, report.kubernetes_inventory_data)
        print_compact_blast_radius(report, fixable_only=fixable_only, page=compact_page)
        print_compact_graph_findings(report)

    # AI enrichment output (both modes)
    if report.executive_summary:
        con.print("\n[bold]Executive Summary (AI-Generated)[/bold]")
        con.print(Panel.fit(report.executive_summary, border_style="cyan"))
    if report.ai_threat_chains:
        con.print("\n[bold]Threat Chain Analysis (AI-Generated)[/bold]")
        for chain in report.ai_threat_chains:
            con.print(Panel(chain, border_style="red dim"))
    # AI skill analysis output (if enriched)
    _emit_skill_analysis(_skill_audit_obj, con)

    if verbose:
        print_remediation_plan(report)
        render_cis_findings_from_context(ctx)
        print_export_hint(report)
    else:
        print_compact_remediation(report, page=compact_page)
        print_compact_cis_posture(report)
        print_compact_compliance_section(report, compliance_enabled=bool(kwargs.get("compliance_enabled")))
        print_compact_export_hint(report)
    print_scan_next_steps(con, report, quiet=quiet, target=str(kwargs.get("next_steps_target") or "."))


def _emit_stdout_standard(blast_radii: Any, exclude_unfixable: Any, offline_html: Any, output_format: Any, report: Any) -> bool:
    if output_format == "cyclonedx":
        sys.stdout.write(json.dumps(to_cyclonedx(report), indent=2))
        return True
    elif output_format == "sarif":
        sys.stdout.write(json.dumps(to_sarif(report, exclude_unfixable=exclude_unfixable), indent=2))
        return True
    elif output_format == "spdx":
        sys.stdout.write(json.dumps(to_spdx(report), indent=2))
        return True
    elif output_format == "spdx2":
        sys.stdout.write(json.dumps(to_spdx2(report), indent=2))
        return True
    elif output_format == "html":
        from agent_bom.output import to_html

        sys.stdout.write(to_html(report, blast_radii, offline_assets=offline_html))
        return True
    elif output_format == "pdf":
        click.echo("Error: --format pdf requires --output/-o (cannot write PDF to stdout)", err=True)
        sys.exit(2)
        return True
    elif output_format == "prometheus":
        sys.stdout.write(to_prometheus(report, blast_radii))
        return True
    return False
