"""Console frameworks rendering helpers."""

from __future__ import annotations

from collections import Counter

from rich.rule import Rule
from rich.table import Table

from agent_bom.models import AIBOMReport
from agent_bom.output.console_style import _console
from agent_bom.output.finding_views import (
    cve_findings,
)


def print_threat_frameworks(report: AIBOMReport) -> None:
    """Print framework coverage using each catalog's existing order and styling."""
    findings = cve_findings(report)
    if not findings:
        return
    sections = (
        ("owasp_tags", _print_owasp),
        ("attack_tags", _print_attack),
        ("atlas_tags", _print_atlas),
        ("nist_ai_rmf_tags", _print_nist),
        ("owasp_mcp_tags", _print_owasp_mcp),
        ("owasp_agentic_tags", _print_owasp_agentic),
        ("eu_ai_act_tags", _print_eu_ai_act),
        ("nist_csf_tags", _print_nist_csf),
        ("iso_27001_tags", _print_iso_27001),
        ("soc2_tags", _print_soc2),
        ("cis_tags", _print_cis),
    )
    counts = {attr: Counter(tag for finding in findings for tag in getattr(finding, attr)) for attr, _ in sections}
    if not any(counts.values()):
        return
    _console().print()
    _console().print(Rule("Threat Framework Coverage", style="bold"))
    _console().print()
    for attr, render in sections:
        render(counts[attr])
    _console().print()


def _print_owasp(owasp_counts: Counter[str]) -> None:
    from agent_bom.owasp import OWASP_LLM_TOP10

    if owasp_counts:
        owasp_table = Table(title="OWASP LLM Top 10", title_style="bold purple", border_style="dim")
        owasp_table.add_column("Code", width=7, style="bold purple")
        owasp_table.add_column("Category", width=36)
        owasp_table.add_column("Findings", width=9, justify="right")
        owasp_table.add_column("", width=20)

        for code in sorted(OWASP_LLM_TOP10.keys()):
            count = owasp_counts.get(code, 0)
            name = OWASP_LLM_TOP10[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                owasp_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                owasp_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(owasp_table)


def _print_attack(attack_counts: Counter[str]) -> None:
    from agent_bom.mitre_attack import ATTACK_TECHNIQUES

    if attack_counts:
        attack_table = Table(title="MITRE ATT&CK Enterprise", title_style="bold red", border_style="dim")
        attack_table.add_column("Technique", width=12, style="bold red")
        attack_table.add_column("Name", width=44)
        attack_table.add_column("Findings", width=9, justify="right")
        attack_table.add_column("", width=20)

        for code in sorted(attack_counts.keys()):
            count = attack_counts[code]
            name = ATTACK_TECHNIQUES.get(code, "Unknown")
            bar_len = min(count, 16)
            bar = "[red]" + "█" * bar_len + "[/red]"
            attack_table.add_row(code, name, f"[bold]{count}[/bold]", bar)

        _console().print(attack_table)


def _print_atlas(atlas_counts: Counter[str]) -> None:
    from agent_bom.atlas import ATLAS_TECHNIQUES

    if atlas_counts:
        atlas_table = Table(title="MITRE ATLAS (AI/ML)", title_style="bold cyan", border_style="dim")
        atlas_table.add_column("Technique", width=12, style="bold cyan")
        atlas_table.add_column("Name", width=38)
        atlas_table.add_column("Findings", width=9, justify="right")
        atlas_table.add_column("", width=20)

        for code in sorted(ATLAS_TECHNIQUES.keys()):
            count = atlas_counts.get(code, 0)
            name = ATLAS_TECHNIQUES[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                atlas_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                atlas_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(atlas_table)


def _print_nist(nist_counts: Counter[str]) -> None:
    from agent_bom.nist_ai_rmf import NIST_AI_RMF

    if nist_counts:
        nist_table = Table(title="NIST AI RMF 1.0", title_style="bold green", border_style="dim")
        nist_table.add_column("Subcategory", width=14, style="bold green")
        nist_table.add_column("Description", width=46)
        nist_table.add_column("Findings", width=9, justify="right")
        nist_table.add_column("", width=20)

        for sid in sorted(NIST_AI_RMF.keys()):
            count = nist_counts.get(sid, 0)
            name = NIST_AI_RMF[sid]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                nist_table.add_row(sid, name, f"[bold]{count}[/bold]", bar)
            else:
                nist_table.add_row(f"[dim]{sid}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(nist_table)


def _print_owasp_mcp(owasp_mcp_counts: Counter[str]) -> None:
    if owasp_mcp_counts:
        from agent_bom.owasp_mcp import OWASP_MCP_TOP10

        mcp_table = Table(title="OWASP MCP Top 10", title_style="bold yellow", border_style="dim")
        mcp_table.add_column("Code", width=7, style="bold yellow")
        mcp_table.add_column("Risk", width=42)
        mcp_table.add_column("Findings", width=9, justify="right")
        mcp_table.add_column("", width=20)

        for code in sorted(OWASP_MCP_TOP10.keys()):
            count = owasp_mcp_counts.get(code, 0)
            name = OWASP_MCP_TOP10[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                mcp_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                mcp_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(mcp_table)


def _print_owasp_agentic(owasp_agentic_counts: Counter[str]) -> None:
    if owasp_agentic_counts:
        from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10

        agentic_table = Table(title="OWASP Agentic Top 10", title_style="bold magenta", border_style="dim")
        agentic_table.add_column("Code", width=7, style="bold magenta")
        agentic_table.add_column("Risk", width=42)
        agentic_table.add_column("Findings", width=9, justify="right")
        agentic_table.add_column("", width=20)

        for code in sorted(OWASP_AGENTIC_TOP10.keys()):
            count = owasp_agentic_counts.get(code, 0)
            name = OWASP_AGENTIC_TOP10[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                agentic_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                agentic_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(agentic_table)


def _print_eu_ai_act(eu_ai_act_counts: Counter[str]) -> None:
    if eu_ai_act_counts:
        from agent_bom.eu_ai_act import EU_AI_ACT

        eu_table = Table(title="EU AI Act", title_style="bold blue", border_style="dim")
        eu_table.add_column("Article", width=9, style="bold blue")
        eu_table.add_column("Description", width=42)
        eu_table.add_column("Findings", width=9, justify="right")
        eu_table.add_column("", width=20)

        for code in sorted(EU_AI_ACT.keys()):
            count = eu_ai_act_counts.get(code, 0)
            name = EU_AI_ACT[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                eu_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                eu_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(eu_table)


def _print_nist_csf(nist_csf_counts: Counter[str]) -> None:
    if nist_csf_counts:
        from agent_bom.nist_csf import NIST_CSF

        csf_table = Table(title="NIST CSF 2.0", title_style="bold bright_green", border_style="dim")
        csf_table.add_column("Category", width=12, style="bold bright_green")
        csf_table.add_column("Description", width=42)
        csf_table.add_column("Findings", width=9, justify="right")
        csf_table.add_column("", width=20)

        for code in sorted(NIST_CSF.keys()):
            count = nist_csf_counts.get(code, 0)
            name = NIST_CSF[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "\u2588" * bar_len + "[/red]"
                csf_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                csf_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]\u2014[/dim]", "")

        _console().print(csf_table)


def _print_iso_27001(iso_27001_counts: Counter[str]) -> None:
    if iso_27001_counts:
        from agent_bom.iso_27001 import ISO_27001

        iso_table = Table(title="ISO 27001:2022", title_style="bold bright_cyan", border_style="dim")
        iso_table.add_column("Control", width=9, style="bold bright_cyan")
        iso_table.add_column("Description", width=42)
        iso_table.add_column("Findings", width=9, justify="right")
        iso_table.add_column("", width=20)

        for code in sorted(ISO_27001.keys()):
            count = iso_27001_counts.get(code, 0)
            name = ISO_27001[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "\u2588" * bar_len + "[/red]"
                iso_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                iso_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]\u2014[/dim]", "")

        _console().print(iso_table)


def _print_soc2(soc2_counts: Counter[str]) -> None:
    if soc2_counts:
        from agent_bom.soc2 import SOC2_TSC

        soc2_table = Table(title="SOC 2 TSC", title_style="bold bright_yellow", border_style="dim")
        soc2_table.add_column("Criteria", width=9, style="bold bright_yellow")
        soc2_table.add_column("Description", width=42)
        soc2_table.add_column("Findings", width=9, justify="right")
        soc2_table.add_column("", width=20)

        for code in sorted(SOC2_TSC.keys()):
            count = soc2_counts.get(code, 0)
            name = SOC2_TSC[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "\u2588" * bar_len + "[/red]"
                soc2_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                soc2_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]\u2014[/dim]", "")

        _console().print(soc2_table)


def _print_cis(cis_counts: Counter[str]) -> None:
    if cis_counts:
        from agent_bom.cis_controls import CIS_CONTROLS

        cis_table = Table(title="CIS Controls v8", title_style="bold bright_magenta", border_style="dim")
        cis_table.add_column("Safeguard", width=12, style="bold bright_magenta")
        cis_table.add_column("Description", width=42)
        cis_table.add_column("Findings", width=9, justify="right")
        cis_table.add_column("", width=20)

        for code in sorted(CIS_CONTROLS.keys()):
            count = cis_counts.get(code, 0)
            name = CIS_CONTROLS[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "\u2588" * bar_len + "[/red]"
                cis_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                cis_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]\u2014[/dim]", "")

        _console().print(cis_table)
