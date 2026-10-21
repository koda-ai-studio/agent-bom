"""Output formatters for AI-BOM reports."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from agent_bom.core.severity import SEVERITY_THRESHOLD_LABELS, severity_worst_first_rank
from agent_bom.core.suppression_score import risk_rank_key
from agent_bom.core.terminal import safe_emoji as safe_emoji
from agent_bom.models import AgentStatus, AIBOMReport, Severity
from agent_bom.output.cis_posture import (
    ERROR,
    INCOMPLETE,
    NOT_EVALUATED,
    PASS,
    cis_pass_rate,
    cis_verdict,
)
from agent_bom.output.compact import _compact_detail, _coverage_bar
from agent_bom.output.console_frameworks import print_threat_frameworks as print_threat_frameworks
from agent_bom.output.console_remediation import build_remediation_plan as build_remediation_plan
from agent_bom.output.console_remediation import print_remediation_plan as print_remediation_plan
from agent_bom.output.console_style import SEVERITY_BADGES as SEVERITY_BADGES
from agent_bom.output.console_style import SEVERITY_TEXT as SEVERITY_TEXT
from agent_bom.output.console_style import _finding_sev_badge as _finding_sev_badge
from agent_bom.output.console_style import _sev_badge as _sev_badge
from agent_bom.output.console_style import console as console
from agent_bom.output.console_summary import _osv_lookup_count as _osv_lookup_count
from agent_bom.output.console_summary import _registry_lookup_count as _registry_lookup_count
from agent_bom.output.console_summary import print_posture_summary as print_posture_summary
from agent_bom.output.console_summary import print_scan_performance_summary as print_scan_performance_summary
from agent_bom.output.console_summary import print_summary as print_summary
from agent_bom.output.dependency_hierarchy import dependency_count_label, dependency_groups
from agent_bom.output.finding_views import (
    cve_findings,
    finding_references,
    finding_severity,
    is_actionable_finding,
    is_package_malicious,
    package_ecosystem,
    package_name,
    package_version,
    sanitize_output_text,
)
from agent_bom.security import sanitize_launch_command, sanitize_path_label


def _console() -> Console:
    """Resolve the shared output console from the compatibility barrel."""
    from agent_bom import output as output_mod

    return output_mod.console


# ─── Centralized severity styling ────────────────────────────────────────────


_THREAT_TAG_COLORS = (
    ("owasp_tags", "purple"),
    ("atlas_tags", "cyan"),
    ("attack_tags", "red"),
    ("nist_ai_rmf_tags", "green"),
    ("owasp_mcp_tags", "yellow"),
    ("owasp_agentic_tags", "magenta"),
    ("eu_ai_act_tags", "blue"),
    ("nist_csf_tags", "bright_green"),
    ("iso_27001_tags", "bright_cyan"),
    ("soc2_tags", "bright_yellow"),
    ("cis_tags", "bright_magenta"),
)


# ─── Console Output ─────────────────────────────────────────────────────────


def print_agent_tree(report: AIBOMReport) -> None:
    """Print the agent → server → package dependency tree."""
    _console().print()
    _console().print(Rule("AI-BOM Dependency Tree", style="blue"))
    _console().print()

    for agent in report.agents:
        status_str = ""
        if agent.status == AgentStatus.INSTALLED_NOT_CONFIGURED:
            status_str = " [yellow][installed, not configured][/yellow]"
        # Compute summary stats
        total_servers = agent.total_mcp_servers
        total_pkgs = sum(len(s.packages) for s in agent.mcp_servers)
        total_creds = sum(len(s.credential_names) for s in agent.mcp_servers)
        stats_parts = [f"{total_servers} server{'s' if total_servers != 1 else ''}"]
        stats_parts.append(f"{total_pkgs} package{'s' if total_pkgs != 1 else ''}")
        if total_creds:
            stats_parts.append(f"{total_creds} credential{'s' if total_creds != 1 else ''}")

        agent_name = escape(sanitize_output_text(agent.name))
        agent_type = escape(sanitize_output_text(agent.agent_type.value))
        agent_tree = Tree(f"\U0001f916 Agent: [bold]{agent_name}[/bold] ({agent_type}){status_str}")
        agent_tree.add(f"[dim]{escape(sanitize_path_label(agent.config_path))}[/dim]")
        sep = " \u00b7 "
        agent_tree.add(f"[dim]{sep.join(stats_parts)}[/dim]")

        for server in agent.mcp_servers:
            vuln_count = server.total_vulnerabilities
            vuln_indicator = f" [red]⚠ {vuln_count} vuln(s)[/red]" if vuln_count else ""
            cred_indicator = f" [yellow]🔑 {len(server.credential_names)} cred(s)[/yellow]" if server.has_credentials else ""

            priv_indicator = ""
            if server.permission_profile and server.permission_profile.is_elevated:
                plevel = server.permission_profile.privilege_level
                if plevel == "critical":
                    priv_indicator = " [red bold]🛡 PRIVILEGED[/red bold]"
                elif plevel == "high":
                    priv_indicator = " [red]🛡 root/shell[/red]"
                elif plevel == "medium":
                    priv_indicator = " [yellow]🛡 elevated[/yellow]"

            registry_indicator = " [green]✓ registry[/green]" if server.registry_verified else " [dim]unknown registry[/dim]"

            server_name = escape(sanitize_output_text(server.name))
            launch = escape(sanitize_launch_command(server.command or "", server.args[:2]))
            server_branch = agent_tree.add(
                f"\U0001f50c MCP Server: [bold cyan]{server_name}[/bold cyan] "
                f"({launch})"
                f"{vuln_indicator}{cred_indicator}{priv_indicator}{registry_indicator}"
            )

            if server.tools:
                tools_branch = server_branch.add(f"[dim]\U0001f527 Tools ({len(server.tools)})[/dim]")
                for tool in server.tools[:10]:  # Limit display
                    tools_branch.add(f"[dim]{escape(sanitize_output_text(tool.name))}[/dim]")
                if len(server.tools) > 10:
                    tools_branch.add(f"[dim]...and {len(server.tools) - 10} more[/dim]")

            if server.packages:
                direct_pkgs, transitive_pkgs, unknown_pkgs = dependency_groups(server.packages)
                pkg_branch = server_branch.add(f"📦 Packages ({len(server.packages)}) — {dependency_count_label(server.packages)}")

                # Show direct packages first
                for pkg in [*direct_pkgs, *unknown_pkgs]:
                    vuln_str = ""
                    if pkg.has_vulnerabilities:
                        vuln_str = f" [red]({len(pkg.vulnerabilities)} vuln(s) - {pkg.max_severity.value})[/red]"
                    sc_str = ""
                    if pkg.scorecard_score is not None:
                        sc_color = "green" if pkg.scorecard_score >= 7.0 else "yellow" if pkg.scorecard_score >= 4.0 else "red"
                        sc_str = f" [{sc_color}]SC:{pkg.scorecard_score:.1f}[/{sc_color}]"
                    pkg_branch.add(
                        f"{escape(sanitize_output_text(pkg.name))}@{escape(sanitize_output_text(pkg.version))} "
                        f"[{escape(sanitize_output_text(pkg.ecosystem))}]{sc_str}{vuln_str}"
                    )

                # Show transitive packages grouped by depth (limit display)
                if transitive_pkgs:
                    transitive_branch = pkg_branch.add(f"[dim]Transitive ({len(transitive_pkgs)})[/dim]")
                    for pkg in transitive_pkgs[:20]:  # Limit to 20 for readability
                        vuln_str = ""
                        if pkg.has_vulnerabilities:
                            vuln_str = f" [red]({len(pkg.vulnerabilities)} vuln(s))[/red]"
                        indent = "  " * pkg.dependency_depth
                        parent_str = f" ← {escape(sanitize_output_text(pkg.parent_package))}" if pkg.parent_package else ""
                        transitive_branch.add(
                            f"[dim]{indent}{escape(sanitize_output_text(pkg.name))}@"
                            f"{escape(sanitize_output_text(pkg.version))}{parent_str}{vuln_str}[/dim]"
                        )
                    if len(transitive_pkgs) > 20:
                        transitive_branch.add(f"[dim]...and {len(transitive_pkgs) - 20} more[/dim]")

            if server.has_credentials:
                cred_branch = server_branch.add("[yellow]\U0001f511 Credentials[/yellow]")
                for cred in server.credential_names:
                    cred_branch.add(f"[yellow]{escape(sanitize_output_text(cred))}[/yellow]")

        _console().print(agent_tree)
        _console().print()


def print_blast_radius(report: AIBOMReport, fixable_only: bool = False) -> None:
    """Print blast radius analysis for vulnerabilities."""
    all_cve = cve_findings(report)
    if not all_cve:
        return

    _console().print()
    _console().print(Rule("Blast Radius Analysis", style="red"))
    _console().print()

    table = Table(title="Vulnerability Impact Chain", expand=True, padding=(0, 1))
    table.add_column("Risk", justify="center", no_wrap=True)
    table.add_column("Vulnerability", no_wrap=True, ratio=3)
    table.add_column("Severity", no_wrap=True)
    table.add_column("EPSS", justify="center", no_wrap=True)
    table.add_column("KEV", justify="center", no_wrap=True)
    table.add_column("Blast", justify="center", no_wrap=True)
    table.add_column("Threats", ratio=3)
    table.add_column("Fix", ratio=2)

    # Filter to actionable findings only — UNKNOWN severity transitive
    # deps with no creds/tools are noise. Users see all with --verbose.
    actionable = [finding for finding in all_cve if is_actionable_finding(finding)]
    # --fixable-only: keep only entries that have a fix available
    if fixable_only:
        actionable = [finding for finding in actionable if finding.fixed_version]
    if not actionable:
        _console().print("  [green]✓ No actionable findings (all transitive/low-severity noise).[/green]")
        if len(all_cve) > 0:
            _console().print(f"  [dim]{len(all_cve)} low-priority findings hidden. Use --verbose to see all.[/dim]")
        return

    for finding in actionable[:25]:  # Top 25 actionable
        sev = finding_severity(finding)
        sev_style = SEVERITY_TEXT.get(sev, "white")
        if finding.fixed_version:
            fix = f"[green]✓ {escape(sanitize_output_text(finding.fixed_version))}[/green]"
        else:
            fix = "[red dim]No fix[/red dim]"

        # EPSS score display
        epss_display = "—"
        if finding.epss_score is not None:
            epss_pct = int(finding.epss_score * 100)
            epss_style = "red bold" if epss_pct >= 70 else "yellow" if epss_pct >= 30 else "dim"
            epss_display = f"[{epss_style}]{epss_pct}%[/{epss_style}]"

        # KEV indicator
        kev_display = "[red bold]🔥[/red bold]" if finding.is_kev else "—"

        # Malicious package indicator
        if is_package_malicious(finding):
            kev_display += " [red bold]☠[/red bold]"

        # Blast column: agents/creds compact
        blast_parts = []
        n_agents = len(finding.affected_agents)
        n_creds = len(finding.exposed_credentials)
        if n_agents:
            blast_parts.append(f"{n_agents}A")
        if n_creds:
            blast_parts.append(f"[yellow]{n_creds}C[/yellow]")
        blast_display = "/".join(blast_parts) if blast_parts else "—"

        # Vulnerability: ID + package on two lines
        vuln_id = escape(sanitize_output_text(finding.cve_id or finding.id))
        package_label = escape(f"{sanitize_output_text(package_name(finding))}@{sanitize_output_text(package_version(finding))}")
        vuln_display = f"{vuln_id}\n[dim]{package_label}[/dim]"

        # Threats column: actual framework tag IDs per finding
        threat_lines = []
        for field, color in _THREAT_TAG_COLORS:
            if tag_values := getattr(finding, field):
                extra = f" +{len(tag_values) - 3}" if len(tag_values) > 3 else ""
                threat_lines.append(f"[{color}]{' '.join(sorted(tag_values)[:3])}{extra}[/{color}]")
        threats_display = "\n".join(threat_lines) if threat_lines else "—"

        table.add_row(
            f"[{sev_style}]{'—' if finding.risk_score is None else format(finding.risk_score, '.1f')}[/{sev_style}]",
            vuln_display,
            _finding_sev_badge(finding),
            epss_display,
            kev_display,
            blast_display,
            threats_display,
            fix,
        )

    _console().print(table)

    if len(all_cve) > 25:
        _console().print(f"\n  [dim]...and {len(all_cve) - 25} more findings. Use --output to export full report.[/dim]")

    # Verification sources — one link per unique CVE
    seen_ids: set[str] = set()
    sources: list[tuple[str, str]] = []
    for finding in all_cve:
        vid = finding.cve_id or finding.id
        if vid in seen_ids:
            continue
        seen_ids.add(vid)
        refs = finding_references(finding)
        if refs:
            sources.append((vid, refs[0]))
        elif vid.startswith("CVE-"):
            sources.append((vid, f"https://osv.dev/vulnerability/{vid}"))
        elif vid.startswith("GHSA-"):
            sources.append((vid, f"https://github.com/advisories/{vid}"))
    if sources:
        _console().print("\n[bold]Verification Sources[/bold]")
        for vid, url in sources[:15]:
            _console().print(f"  [dim]{vid}[/dim]  →  [link={url}]{url}[/link]")
        if len(sources) > 15:
            _console().print(f"  [dim]...and {len(sources) - 15} more (see JSON output for full list)[/dim]")


def print_attack_flow_tree(report: AIBOMReport) -> None:
    """Print per-CVE blast radius chains as Rich Trees."""
    all_cve = cve_findings(report)
    if not all_cve:
        return

    _console().print()
    _console().print(Rule("Attack Flow Chains", style="red"))
    _console().print()

    severity_styles = {Severity.CRITICAL: "red bold", Severity.HIGH: "#e67e22 bold", Severity.MEDIUM: "yellow", Severity.LOW: "dim"}

    for finding in sorted(all_cve, key=risk_rank_key)[:15]:
        sev = finding_severity(finding)
        sev_style = severity_styles.get(sev, "white")
        vuln_id = finding.cve_id or finding.id

        # Root: CVE line
        root_parts = [f"[{sev_style}]{vuln_id}[/{sev_style}]"]
        root_parts.append(f"[{sev_style}]\\[{sev.value}][/{sev_style}]")
        if finding.cvss_score is not None:
            root_parts.append(f"CVSS {finding.cvss_score:.1f}")
        if finding.epss_score is not None:
            pct = int(finding.epss_score * 100)
            root_parts.append(f"EPSS {pct}%")
        if finding.is_kev:
            root_parts.append("[red bold]🔥 KEV[/red bold]")

        cve_tree = Tree(" · ".join(root_parts))

        # Package node
        pkg_label = escape(
            f"{sanitize_output_text(package_name(finding))}@{sanitize_output_text(package_version(finding))} "
            f"({sanitize_output_text(package_ecosystem(finding))})"
        )
        pkg_branch = cve_tree.add(f"[dim]{pkg_label}[/dim]")

        # Server branches
        for raw_server_name in finding.affected_servers:
            server_name = escape(sanitize_output_text(raw_server_name))
            srv_branch = pkg_branch.add(f"\U0001f50c [bold cyan]{server_name}[/bold cyan] [dim](MCP Server)[/dim]")

            # Agents
            for raw_agent_name in finding.affected_agents:
                agent_name = escape(sanitize_output_text(raw_agent_name))
                srv_branch.add(f"\U0001f916 [green]{agent_name}[/green] [dim](Agent)[/dim]")

            # Credentials
            for cred in finding.exposed_credentials:
                srv_branch.add(f"[yellow]🔑 {escape(sanitize_output_text(cred))}[/yellow]")

            # Tools (compact, max 5 per line)
            if finding.exposed_tools:
                tool_names = [escape(sanitize_output_text(tool)) for tool in finding.exposed_tools[:5]]
                extra = f" +{len(finding.exposed_tools) - 5}" if len(finding.exposed_tools) > 5 else ""
                srv_branch.add(f"[dim]🔧 {', '.join(tool_names)}{extra}[/dim]")

        # If no servers, still show agents/creds/tools under package
        if not finding.affected_servers:
            for raw_agent_name in finding.affected_agents:
                agent_name = escape(sanitize_output_text(raw_agent_name))
                pkg_branch.add(f"\U0001f916 [green]{agent_name}[/green] [dim](Agent)[/dim]")
            for cred in finding.exposed_credentials:
                pkg_branch.add(f"[yellow]🔑 {escape(sanitize_output_text(cred))}[/yellow]")
            if finding.exposed_tools:
                tool_names = [escape(sanitize_output_text(tool)) for tool in finding.exposed_tools[:5]]
                extra = f" +{len(finding.exposed_tools) - 5}" if len(finding.exposed_tools) > 5 else ""
                pkg_branch.add(f"[dim]🔧 {', '.join(tool_names)}{extra}[/dim]")

        _console().print(cve_tree)

    remaining = len(all_cve) - 15
    if remaining > 0:
        _console().print(f"\n  [dim]...and {remaining} more findings. Use --output to export full report.[/dim]")
    _console().print()


# ─── Remediation Plan ───────────────────────────────────────────────────────


_CIS_CLOUD_BUNDLES: tuple[tuple[str, str, str], ...] = (
    ("aws", "AWS", "cis_benchmark_data"),
    ("azure", "Azure", "azure_cis_benchmark_data"),
    ("gcp", "GCP", "gcp_cis_benchmark_data"),
    ("snowflake", "Snowflake", "snowflake_cis_benchmark_data"),
    ("databricks", "Databricks Security Best Practices", "databricks_security_data"),
)

_SEV_LABEL: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}
_SEV_TABLE_STYLE: dict[str, str] = {
    "critical": "white on red",
    "high": "white on #e67e22",
    "medium": "black on yellow",
    "low": "white on #555555",
}


_CIS_VERDICT_STYLE = {
    NOT_EVALUATED: "dim",
    ERROR: "bold red",
    INCOMPLETE: "bold yellow",
    PASS: "bold green",
}


def _cis_sev(check: dict) -> str:
    """Normalize a check's severity to a known lowercase band."""
    sev = str(check.get("severity") or "").lower()
    return sev if sev in SEVERITY_THRESHOLD_LABELS else "low"


def _cis_check_sort_key(check: dict) -> tuple[int, int, str, str]:
    """Deterministic ordering: severity, remediation priority, section, id."""
    rem = check.get("remediation") or {}
    priority = rem.get("priority")
    if not isinstance(priority, int):
        priority = 3
    return (
        severity_worst_first_rank(check.get("severity")),
        priority,
        str(check.get("cis_section") or "~"),
        str(check.get("check_id") or ""),
    )


def _cis_evidence(check: dict) -> str:
    """Best available evidence string: prefer affected resource IDs."""
    resources = check.get("resource_ids") or []
    if resources:
        shown = ", ".join(str(r) for r in resources[:4])
        if len(resources) > 4:
            shown += f" (+{len(resources) - 4} more)"
        return _compact_detail(shown, limit=160)
    return _compact_detail(str(check.get("evidence") or "").strip(), limit=160)


def _cis_remediation_line(check: dict) -> str:
    """Resolve the single 'what to do' line for a failed check."""
    rem = check.get("remediation") or {}
    fix_cli = rem.get("fix_cli")
    if fix_cli:
        return str(fix_cli)
    fix_console = rem.get("fix_console")
    if fix_console:
        return f"→ {fix_console}"
    recommendation = str(check.get("recommendation") or "").strip()
    if recommendation:
        return recommendation
    return ""


def print_cis_findings(report: AIBOMReport, *, show_passed: bool = False) -> None:
    """Render CIS benchmark results as a prioritized, grouped FAILED plan.

    Built for large result sets (60+ checks) where a flat table is
    unreadable. For each cloud with benchmark data:

      - A posture header: pass-rate band, passed/evaluated counts, and a
        verdict driven by the highest failing severity.
      - PASS checks are collapsed into a single ``N passed`` summary line
        by default; pass ``show_passed=True`` to list them.
      - FAILED checks lead, grouped by severity (CRITICAL first) then by
        CIS section/domain, each showing a severity badge, check id +
        title, the affected resources (evidence), and a recommendation /
        remediation command (the 'what to do' line).

    Ordering is deterministic so the same report renders identically
    across runs. Emits nothing when no CIS data is present.
    """
    from agent_bom.cloud.cis_remediation import fail_closed_cis_bundle

    con = _console()
    raw_bundles = [(cloud, label, getattr(report, attr, None)) for cloud, label, attr in _CIS_CLOUD_BUNDLES]
    bundles = [
        (c, lbl, fail_closed_cis_bundle(b, cloud=c) if c in {"aws", "azure", "gcp", "snowflake"} else b)
        for c, lbl, b in raw_bundles
        if b and b.get("checks")
    ]
    if not bundles:
        return

    con.print()
    con.print(Rule("Cloud Security Posture", style="bold bright_magenta"))

    for _cloud, label, bundle in bundles:
        checks = bundle.get("checks") or []
        failed = [c for c in checks if str(c.get("status")) == "fail"]
        passed = [c for c in checks if str(c.get("status")) == "pass"]
        errored = [c for c in checks if str(c.get("status")) == "error"]
        actionable = failed + errored
        evaluated = len(failed) + len(passed)
        pass_rate = cis_pass_rate(bundle, checks)

        band = "green" if pass_rate >= 90 else "yellow" if pass_rate >= 70 else "red"

        # Verdict comes from the one shared derivation so this panel and the
        # HTML report can never disagree about the same scan.
        verdict_text = cis_verdict(checks)
        if verdict_text == NOT_EVALUATED:
            band = "dim"
        vstyle = _CIS_VERDICT_STYLE.get(verdict_text) or {
            "CRITICAL": "red bold",
            "HIGH": "#e67e22 bold",
            "MEDIUM": "yellow",
            "LOW": "dim",
        }.get(verdict_text.split()[0], "red bold")
        verdict = f"[{vstyle}]{verdict_text}[/{vstyle}]"

        con.print()
        con.print(
            f"  [bold]{label}[/bold]  {verdict}   "
            f"[{band}]{pass_rate:.0f}% pass[/{band}]  "
            f"[dim]({len(passed)}/{evaluated} checks"
            + (f", {len(failed)} failed" if failed else "")
            + (f", {len(errored)} errored" if errored else "")
            + ")[/dim]"
        )

        if not actionable:
            if verdict_text == NOT_EVALUATED:
                con.print("    [dim]no control produced a pass or a fail — nothing was evaluated[/dim]")
            else:
                con.print(f"    [green]{safe_emoji('✓', 'OK')}[/green] [dim]no failed checks[/dim]")
            if show_passed and passed:
                _print_cis_passed(con, passed)
            continue

        # Top risks: the highest-priority failing check ids, for the header.
        top = sorted(actionable, key=_cis_check_sort_key)[:3]
        top_str = ", ".join(str(c.get("check_id") or "?") for c in top)
        con.print(f"    [dim]top risks:[/dim] {top_str}")

        # Group failed checks by severity, then by CIS section.
        for sev in ("critical", "high", "medium", "low"):
            sev_actionable = [c for c in actionable if _cis_sev(c) == sev]
            if not sev_actionable:
                continue
            badge_style = _SEV_TABLE_STYLE[sev]
            failed_n = sum(1 for c in sev_actionable if c.get("status") == "fail")
            error_n = len(sev_actionable) - failed_n
            summary = ", ".join(
                part for part in (f"{failed_n} failed" if failed_n else "", f"{error_n} unevaluable" if error_n else "") if part
            )
            con.print(f"\n    [{badge_style}] {_SEV_LABEL[sev]} [/{badge_style}] [dim]{summary}[/dim]")

            # Group within severity by section for readability.
            sections: dict[str, list[dict]] = {}
            for c in sorted(sev_actionable, key=_cis_check_sort_key):
                sections.setdefault(str(c.get("cis_section") or "Other"), []).append(c)

            for section in sorted(sections):
                con.print(f"      [bold dim]{section}[/bold dim]")
                for check in sections[section]:
                    rem = check.get("remediation") or {}
                    review = f" [yellow]{safe_emoji('↺', '(review)')} review[/yellow]" if rem.get("requires_human_review") else ""
                    title = str(check.get("title") or "").rstrip(".")
                    con.print(f"        [bold]{check.get('check_id', '')}[/bold]  {title}{review}")
                    evidence = _cis_evidence(check)
                    if evidence:
                        con.print(f"          [dim]evidence:[/dim] {evidence}")
                    fix = _cis_remediation_line(check)
                    if fix:
                        con.print(f"          [cyan]fix:[/cyan] {fix}")

        # Collapsed PASS summary (expandable).
        if passed:
            if show_passed:
                _print_cis_passed(con, passed)
            else:
                con.print(f"\n    [green]{safe_emoji('✓', 'OK')}[/green] [dim]{len(passed)} passed (use --show-passed to list)[/dim]")

    con.print()


def _print_cis_passed(con: Console, passed: list[dict]) -> None:
    """List passed checks compactly, sorted by check id (deterministic)."""
    con.print(f"\n    [green]Passed ({len(passed)}):[/green]")
    for check in sorted(passed, key=lambda c: str(c.get("check_id") or "")):
        title = str(check.get("title") or "").rstrip(".")
        con.print(f"      [green]{safe_emoji('✓', 'OK')}[/green] [dim]{check.get('check_id', '')}  {title}[/dim]")


def print_export_hint(report: AIBOMReport) -> None:
    """Print an AI-BOM identity footer with threat framework badge, explore links, and export hints."""

    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.mitre_attack import ATTACK_TECHNIQUES
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.owasp import OWASP_LLM_TOP10

    lines: list[str] = []

    # ── Threat Framework Coverage Badge ──
    owasp_hit: set[str] = set()
    atlas_hit: set[str] = set()
    attack_hit: set[str] = set()
    nist_hit: set[str] = set()
    owasp_mcp_hit: set[str] = set()
    owasp_agentic_hit: set[str] = set()
    eu_ai_act_hit: set[str] = set()
    nist_csf_hit: set[str] = set()
    iso_27001_hit: set[str] = set()
    soc2_hit: set[str] = set()
    cis_hit: set[str] = set()
    for br in cve_findings(report):
        owasp_hit.update(br.owasp_tags)
        atlas_hit.update(br.atlas_tags)
        attack_hit.update(br.attack_tags)
        nist_hit.update(br.nist_ai_rmf_tags)
        owasp_mcp_hit.update(br.owasp_mcp_tags)
        owasp_agentic_hit.update(br.owasp_agentic_tags)
        eu_ai_act_hit.update(br.eu_ai_act_tags)
        nist_csf_hit.update(br.nist_csf_tags)
        iso_27001_hit.update(br.iso_27001_tags)
        soc2_hit.update(br.soc2_tags)
        cis_hit.update(br.cis_tags)

    from agent_bom.cis_controls import CIS_CONTROLS as _CIS_CONTROLS
    from agent_bom.eu_ai_act import EU_AI_ACT as _EU_AI_ACT
    from agent_bom.iso_27001 import ISO_27001 as _ISO_27001
    from agent_bom.nist_csf import NIST_CSF as _NIST_CSF
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10 as _OWASP_AGENTIC
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10
    from agent_bom.soc2 import SOC2_TSC as _SOC2_TSC

    owasp_total = len(OWASP_LLM_TOP10)
    atlas_total = len(ATLAS_TECHNIQUES)
    attack_total = len(ATTACK_TECHNIQUES)
    nist_total = len(NIST_AI_RMF)
    owasp_mcp_total = len(OWASP_MCP_TOP10)
    owasp_agentic_total = len(_OWASP_AGENTIC)
    eu_ai_act_total = len(_EU_AI_ACT)
    nist_csf_total = len(_NIST_CSF)
    iso_27001_total = len(_ISO_27001)
    soc2_total = len(_SOC2_TSC)
    cis_total = len(_CIS_CONTROLS)

    if cve_findings(report):
        lines.append("[bold]AI Threat Framework Coverage[/bold]")
        lines.append("")

        # OWASP bar
        owasp_pct = int(len(owasp_hit) / owasp_total * 100) if owasp_total else 0
        owasp_bar = _coverage_bar(len(owasp_hit), owasp_total, "purple")
        lines.append(
            f"  [bold purple]OWASP LLM Top 10[/bold purple]  {owasp_bar}  [purple]{len(owasp_hit)}/{owasp_total}[/purple] ({owasp_pct}%)"
        )

        # ATT&CK Enterprise bar
        attack_pct = int(len(attack_hit) / attack_total * 100) if attack_total else 0
        attack_bar = _coverage_bar(len(attack_hit), attack_total, "red")
        lines.append(f"  [bold red]MITRE ATT&CK     [/bold red]  {attack_bar}  [red]{len(attack_hit)}/{attack_total}[/red] ({attack_pct}%)")

        # ATLAS bar
        atlas_pct = int(len(atlas_hit) / atlas_total * 100) if atlas_total else 0
        atlas_bar = _coverage_bar(len(atlas_hit), atlas_total, "cyan")
        lines.append(f"  [bold cyan]MITRE ATLAS      [/bold cyan]  {atlas_bar}  [cyan]{len(atlas_hit)}/{atlas_total}[/cyan] ({atlas_pct}%)")

        # NIST bar
        nist_pct = int(len(nist_hit) / nist_total * 100) if nist_total else 0
        nist_bar = _coverage_bar(len(nist_hit), nist_total, "green")
        lines.append(f"  [bold green]NIST AI RMF 1.0  [/bold green]  {nist_bar}  [green]{len(nist_hit)}/{nist_total}[/green] ({nist_pct}%)")

        # OWASP MCP bar
        owasp_mcp_pct = int(len(owasp_mcp_hit) / owasp_mcp_total * 100) if owasp_mcp_total else 0
        owasp_mcp_bar = _coverage_bar(len(owasp_mcp_hit), owasp_mcp_total, "yellow")
        lines.append(
            f"  [bold yellow]OWASP MCP Top 10 [/bold yellow]  {owasp_mcp_bar}"
            f"  [yellow]{len(owasp_mcp_hit)}/{owasp_mcp_total}[/yellow] ({owasp_mcp_pct}%)"
        )

        # OWASP Agentic bar
        owasp_agentic_pct = int(len(owasp_agentic_hit) / owasp_agentic_total * 100) if owasp_agentic_total else 0
        owasp_agentic_bar = _coverage_bar(len(owasp_agentic_hit), owasp_agentic_total, "magenta")
        lines.append(
            f"  [bold magenta]OWASP Agentic T10[/bold magenta]  {owasp_agentic_bar}"
            f"  [magenta]{len(owasp_agentic_hit)}/{owasp_agentic_total}[/magenta] ({owasp_agentic_pct}%)"
        )

        # EU AI Act bar
        eu_ai_act_pct = int(len(eu_ai_act_hit) / eu_ai_act_total * 100) if eu_ai_act_total else 0
        eu_ai_act_bar = _coverage_bar(len(eu_ai_act_hit), eu_ai_act_total, "blue")
        lines.append(
            f"  [bold blue]EU AI Act         [/bold blue]  {eu_ai_act_bar}"
            f"  [blue]{len(eu_ai_act_hit)}/{eu_ai_act_total}[/blue] ({eu_ai_act_pct}%)"
        )

        # NIST CSF 2.0 bar
        nist_csf_pct = int(len(nist_csf_hit) / nist_csf_total * 100) if nist_csf_total else 0
        nist_csf_bar = _coverage_bar(len(nist_csf_hit), nist_csf_total, "bright_green")
        lines.append(
            f"  [bold bright_green]NIST CSF 2.0      [/bold bright_green]  {nist_csf_bar}"
            f"  [bright_green]{len(nist_csf_hit)}/{nist_csf_total}[/bright_green] ({nist_csf_pct}%)"
        )

        # ISO 27001:2022 bar
        iso_27001_pct = int(len(iso_27001_hit) / iso_27001_total * 100) if iso_27001_total else 0
        iso_27001_bar = _coverage_bar(len(iso_27001_hit), iso_27001_total, "bright_cyan")
        lines.append(
            f"  [bold bright_cyan]ISO 27001:2022    [/bold bright_cyan]  {iso_27001_bar}"
            f"  [bright_cyan]{len(iso_27001_hit)}/{iso_27001_total}[/bright_cyan] ({iso_27001_pct}%)"
        )

        # SOC 2 TSC bar
        soc2_pct = int(len(soc2_hit) / soc2_total * 100) if soc2_total else 0
        soc2_bar = _coverage_bar(len(soc2_hit), soc2_total, "bright_yellow")
        lines.append(
            f"  [bold bright_yellow]SOC 2 TSC         [/bold bright_yellow]  {soc2_bar}"
            f"  [bright_yellow]{len(soc2_hit)}/{soc2_total}[/bright_yellow] ({soc2_pct}%)"
        )

        # CIS Controls v8 bar
        cis_pct = int(len(cis_hit) / cis_total * 100) if cis_total else 0
        cis_bar = _coverage_bar(len(cis_hit), cis_total, "bright_magenta")
        lines.append(
            f"  [bold bright_magenta]CIS Controls v8   [/bold bright_magenta]  {cis_bar}"
            f"  [bright_magenta]{len(cis_hit)}/{cis_total}[/bright_magenta] ({cis_pct}%)"
        )

        lines.append("")

    # ── Summary ──
    vuln_color = "red" if report.total_vulnerabilities > 0 else "green"
    lines.append("[bold]AI Infrastructure Security Report[/bold]")
    lines.append(
        f"  [dim]{report.total_agents} agents · {report.total_servers} MCP servers · "
        f"{report.total_packages} packages ·[/dim] "
        f"[bold {vuln_color}]{report.total_vulnerabilities} vulnerabilities[/bold {vuln_color}]"
    )
    lines.append("")

    # ── Contextual next steps ──
    lines.append("[bold]Next steps[/bold]")
    if report.total_vulnerabilities > 0:
        lines.append("  [green]agent-bom scan --remediate fix.md[/green]               [dim]Generate fix commands[/dim]")
        lines.append("  [green]agent-bom scan -f sarif -o results.sarif[/green]        [dim]Upload to GitHub Security[/dim]")
    if report.total_servers > 0:
        lines.append("  [green]agent-bom runtime proxy -- npx @mcp/server ...[/green]  [dim]Enforce MCP traffic[/dim]")
    lines.append("  [green]agent-bom scan -f html -o report.html[/green]           [dim]Interactive HTML report[/dim]")
    lines.append("  [green]agent-bom scan -f pdf -o report.pdf[/green]             [dim]Audit-ready PDF export[/dim]")
    lines.append("")

    # ── Export (compact) ──
    lines.append("[bold]Export[/bold]")
    lines.append("  [green]-f[/green] json · cyclonedx · spdx · sarif · html · pdf · junit   [dim]19 formats[/dim]")

    _console().print()
    _console().print(Panel("\n".join(lines), border_style="blue", padding=(1, 2)))


# The compact output family moved to agent_bom/output/compact.py as Phase 1a
# of the #1522 monolith split. Re-exported at the bottom of this file for
# backward compatibility.


# ─── Diff Output ─────────────────────────────────────────────────────────────


def print_diff(diff: dict, *, quiet: bool = False) -> None:
    """Print a human-readable diff between two scan reports."""
    summary = diff["summary"]
    baseline_ts = diff["baseline_generated_at"]
    current_ts = diff["current_generated_at"]

    parts = []
    if summary["new_findings"]:
        parts.append(f"[red bold]+{summary['new_findings']} new[/red bold]")
    if summary["resolved_findings"]:
        parts.append(f"[green bold]-{summary['resolved_findings']} resolved[/green bold]")
    if summary["unchanged_findings"]:
        parts.append(f"[dim]{summary['unchanged_findings']} unchanged[/dim]")
    if summary["new_packages"]:
        parts.append(f"[yellow]{summary['new_packages']} new package(s)[/yellow]")
    if summary["removed_packages"]:
        parts.append(f"[dim]{summary['removed_packages']} removed package(s)[/dim]")
    inventory_diff = diff.get("inventory_diff", {})
    inv_summary = inventory_diff.get("summary", {}) if isinstance(inventory_diff, dict) else {}
    if inv_summary.get("new_servers"):
        parts.append(f"[cyan]{inv_summary['new_servers']} new server(s)[/cyan]")
    if inv_summary.get("removed_servers"):
        parts.append(f"[dim]{inv_summary['removed_servers']} removed server(s)[/dim]")
    if inv_summary.get("changed_servers"):
        parts.append(f"[magenta]{inv_summary['changed_servers']} changed server fingerprint(s)[/magenta]")
    if inv_summary.get("changed_tools"):
        parts.append(f"[magenta]{inv_summary['changed_tools']} changed tool(s)[/magenta]")
    if inv_summary.get("changed_resources"):
        parts.append(f"[magenta]{inv_summary['changed_resources']} changed resource(s)[/magenta]")
    if inv_summary.get("new_tools"):
        parts.append(f"[cyan]{inv_summary['new_tools']} new tool(s)[/cyan]")
    if inv_summary.get("new_resources"):
        parts.append(f"[cyan]{inv_summary['new_resources']} new resource(s)[/cyan]")
    if inv_summary.get("new_relationships"):
        parts.append(f"[cyan]{inv_summary['new_relationships']} new relationship(s)[/cyan]")
    if inv_summary.get("removed_relationships"):
        parts.append(f"[dim]{inv_summary['removed_relationships']} removed relationship(s)[/dim]")

    if quiet:
        if parts:
            _console().print("  •  ".join(parts))
        else:
            _console().print("No changes since baseline.")
        return

    _console().print(f"\n[bold blue]📊 Scan Diff[/bold blue]  [dim]{baseline_ts}[/dim] → [dim]{current_ts}[/dim]\n")

    if parts:
        _console().print("  " + "  •  ".join(parts) + "\n")
    else:
        _console().print("  [green]No changes since baseline.[/green]\n")
        return

    severity_styles = {
        "CRITICAL": "red bold",
        "HIGH": "#e67e22 bold",
        "MEDIUM": "yellow",
        "LOW": "dim",
    }

    if diff["new"]:
        _console().print(f"  [red bold]New findings ({len(diff['new'])}):[/red bold]")
        for br in diff["new"][:20]:
            sev = br.get("severity", "UNKNOWN")
            style = severity_styles.get(sev, "white")
            kev = " [red bold][KEV][/red bold]" if br.get("is_kev") else ""
            ai = " [magenta][AI-RISK][/magenta]" if br.get("ai_risk_context") else ""
            fix = f" → fix: {br['fixed_version']}" if br.get("fixed_version") else " (no fix)"
            _console().print(
                f"    [+] [{style}]{br.get('vulnerability_id', '?')}[/{style}]  {br.get('package', '?')}  [{sev}]{kev}{ai}[dim]{fix}[/dim]"
            )
        if len(diff["new"]) > 20:
            _console().print(f"    [dim]...and {len(diff['new']) - 20} more[/dim]")
        _console().print()

    if diff["resolved"]:
        _console().print(f"  [green]Resolved findings ({len(diff['resolved'])}):[/green]")
        for br in diff["resolved"][:10]:
            _console().print(f"    [-] [dim]{br.get('vulnerability_id', '?')}  {br.get('package', '?')}[/dim]")
        _console().print()

    if diff["new_packages"]:
        _console().print(f"  [yellow]New packages added ({len(diff['new_packages'])}):[/yellow]")
        for pkg in diff["new_packages"][:10]:
            _console().print(f"    [+] [dim]{pkg}[/dim]")
        _console().print()

    if diff["removed_packages"]:
        _console().print(f"  [dim]Packages removed ({len(diff['removed_packages'])}):[/dim]")
        for pkg in diff["removed_packages"][:10]:
            _console().print(f"    [-] [dim]{pkg}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("changed_servers"):
        _console().print(f"  [magenta]Server fingerprint changes ({len(inventory_diff['changed_servers'])}):[/magenta]")
        for server in inventory_diff["changed_servers"][:10]:
            _console().print(f"    [~] [dim]{server.get('name') or server.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("changed_tools"):
        _console().print(f"  [magenta]Changed tools ({len(inventory_diff['changed_tools'])}):[/magenta]")
        for tool in inventory_diff["changed_tools"][:10]:
            _console().print(f"    [~] [dim]{tool.get('name') or tool.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("changed_resources"):
        _console().print(f"  [magenta]Changed resources ({len(inventory_diff['changed_resources'])}):[/magenta]")
        for resource in inventory_diff["changed_resources"][:10]:
            _console().print(f"    [~] [dim]{resource.get('uri') or resource.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("new_tools"):
        _console().print(f"  [cyan]New tools ({len(inventory_diff['new_tools'])}):[/cyan]")
        for tool in inventory_diff["new_tools"][:10]:
            _console().print(f"    [+] [dim]{tool.get('name') or tool.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("new_resources"):
        _console().print(f"  [cyan]New resources ({len(inventory_diff['new_resources'])}):[/cyan]")
        for resource in inventory_diff["new_resources"][:10]:
            _console().print(f"    [+] [dim]{resource.get('uri') or resource.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("new_relationships"):
        _console().print(f"  [cyan]New relationships ({len(inventory_diff['new_relationships'])}):[/cyan]")
        for relationship in inventory_diff["new_relationships"][:10]:
            _console().print(f"    [+] [dim]{relationship.get('from')} -[{relationship.get('type')}]-> {relationship.get('to')}[/dim]")
        _console().print()


# ─── Policy Output ──────────────────────────────────────────────────────────


def print_policy_results(policy_result: dict) -> None:
    """Print policy evaluation results to console."""
    name = policy_result["policy_name"]
    failures = policy_result["failures"]
    warnings = policy_result["warnings"]
    passed = policy_result["passed"]

    status = "[green]PASS[/green]" if passed else "[red bold]FAIL[/red bold]"
    _console().print(f"\n[bold]📋 Policy: {name}[/bold]  {status}\n")

    if warnings:
        _console().print(f"  [yellow]⚠ {len(warnings)} warning(s):[/yellow]")
        for v in warnings[:10]:
            _console().print(f"    [yellow]WARN[/yellow]  [{v['rule_id']}]  {v['vulnerability_id']}  {v['package']}  [{v['severity']}]")
            _console().print(f"           [dim]{v['rule_description']}[/dim]")
        _console().print()

    if failures:
        _console().print(f"  [red bold]✗ {len(failures)} failure(s):[/red bold]")
        for v in failures[:10]:
            kev = " [red bold][KEV][/red bold]" if v.get("is_kev") else ""
            ai = " [magenta][AI-RISK][/magenta]" if v.get("ai_risk_context") else ""
            _console().print(
                f"    [red bold]FAIL[/red bold]  [{v['rule_id']}]  {v['vulnerability_id']}  {v['package']}  [{v['severity']}]{kev}{ai}"
            )
            _console().print(f"           [dim]{v['rule_description']}[/dim]")
        if len(failures) > 10:
            _console().print(f"    [dim]...and {len(failures) - 10} more failures[/dim]")
        _console().print()

    if passed and not warnings:
        _console().print("  [green]✓ All policy rules passed.[/green]\n")


# ─── Severity Chart ─────────────────────────────────────────────────────────


def print_severity_chart(report: AIBOMReport) -> None:
    """Print an ASCII severity distribution bar chart."""
    all_cve = cve_findings(report)
    if not all_cve:
        return

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in all_cve:
        sev = finding_severity(finding).value.upper()
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())
    if total == 0:
        return

    _console().print()
    _console().print(Rule("Severity Distribution", style="bold"))
    _console().print()
    max_count = max(counts.values()) or 1
    bar_width = 30
    styles = {
        "CRITICAL": "red bold",
        "HIGH": "#e67e22 bold",
        "MEDIUM": "yellow",
        "LOW": "dim",
    }

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = counts[sev]
        bar_len = int(bar_width * count / max_count) if count else 0
        bar = "█" * bar_len
        style = styles[sev]
        pct = int(100 * count / total) if total else 0
        _console().print(f"  [{style}]{sev:8}[/{style}]  [{style}]{bar:<{bar_width}}[/{style}]  [dim]{count:3} ({pct}%)[/dim]")
    _console().print()
