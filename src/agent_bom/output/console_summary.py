"""Console summary rendering helpers."""

from __future__ import annotations

from collections import Counter

from rich.panel import Panel
from rich.table import Table

from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.finding import Finding, FindingType
from agent_bom.models import AgentStatus, AIBOMReport
from agent_bom.output.cis_posture import (
    finding_free_posture,
)
from agent_bom.output.console_style import _console
from agent_bom.output.finding_views import (
    active_cve_findings,
    cve_findings,
    finding_severity,
    package_ecosystem,
    package_name,
    package_version,
)
from agent_bom.output.graph_coverage_panel import print_graph_coverage_gaps, print_scan_notes


def print_summary(report: AIBOMReport) -> None:
    """Print a summary of the agent-bom scan report to console."""
    from agent_bom.output.brand_tokens import PRODUCT_NAME, REPORT_TITLE

    _console().print("\n")
    _console().print(
        Panel.fit(
            f"[bold]{REPORT_TITLE}[/bold]\n"
            f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"{PRODUCT_NAME} v{report.tool_version}",
            border_style="blue",
        )
    )

    # Summary stats
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Agents discovered", str(report.total_agents))
    table.add_row("MCP servers", str(report.total_servers))
    table.add_row("Total packages", str(report.total_packages))
    table.add_row("Vulnerabilities", str(report.total_vulnerabilities))
    # Scope-labelled: ``critical_vulns`` counts blast radii, so a critical
    # non-CVE finding (malicious package, CIS FAIL, toxic combination) is not in
    # it. The posture headline a few lines below counts every finding category,
    # so an unscoped "Critical findings" here contradicts it on the same screen.
    table.add_row("Critical package CVEs", str(len(report.critical_vulns)))

    _add_ai_summary(table, report)

    _add_project_summary(table, report)

    _add_repo_summary(table, report)

    _add_model_summary(table, report)

    _add_lookup_summary(table, report)

    _console().print(table)

    _print_coverage_warnings(report)


def print_scan_performance_summary(report: AIBOMReport) -> None:
    """Print a compact cache/performance summary when available."""
    perf = report.scan_performance_data or {}
    osv = perf.get("osv") or {}
    registry = perf.get("registry") or {}
    advisory = perf.get("advisory_coverage") or {}
    if not osv and not registry and not advisory:
        return

    lines: list[str] = []
    if osv and _osv_lookup_count(osv) > 0:
        osv_line = (
            f"OSV cache {osv.get('cache_hits', 0)} hit / {osv.get('cache_misses', 0)} miss"
            f" · {osv.get('packages_queried', 0)} package lookup(s)"
        )
        hit_rate = osv.get("cache_hit_rate_pct")
        if hit_rate is not None:
            osv_line += f" · {hit_rate}% hit rate"
        if osv.get("lookup_errors", 0):
            osv_line += f" · {osv.get('lookup_errors', 0)} lookup error(s)"
        lines.append(osv_line)
    if registry and _registry_lookup_count(registry) > 0:
        reg_line = (
            f"Registry cache {registry.get('cache_hits', 0)} hit / {registry.get('cache_misses', 0)} miss"
            f" · {registry.get('network_requests', 0)} network request(s)"
        )
        reg_rate = registry.get("cache_hit_rate_pct")
        if reg_rate is not None:
            reg_line += f" · {reg_rate}% hit rate"
        if registry.get("npm_rate_limit_short_circuits", 0):
            reg_line += f" · {registry.get('npm_rate_limit_short_circuits', 0)} npm cooldown skip(s)"
        lines.append(reg_line)
    if advisory:
        primary = advisory.get("primary_sources", {})
        enrich = advisory.get("enrichment_sources", {})
        primary_line = ", ".join(f"{source} {count}" for source, count in primary.items() if count) or "no primary sources"
        enrich_line = ", ".join(f"{source} {count}" for source, count in enrich.items() if count) or "no enrichment"
        lines.append(
            f"Threat intel {primary_line} · {enrich_line} · {advisory.get('records_with_multiple_sources', 0)} multi-source record(s)"
        )
    if not lines:
        return
    _console().print("\n[dim]Cache & lookup reuse[/dim]")
    for line in lines:
        _console().print(f"  [dim]{line}[/dim]")


def _osv_lookup_count(osv: dict) -> int:
    """Return online OSV lookups represented by a performance payload."""
    return int(osv.get("packages_queried") or osv.get("cache_hits", 0) + osv.get("cache_misses", 0) or 0)


def _registry_lookup_count(registry: dict) -> int:
    """Return registry lookups represented by a performance payload."""
    return int(registry.get("network_requests") or registry.get("cache_hits", 0) + registry.get("cache_misses", 0) or 0)


def print_posture_summary(report: AIBOMReport) -> None:
    """Print a high-level security posture summary with ecosystem and credential aggregation."""
    coverage = report.scan_performance_data or {}
    scan_run = effective_scan_run(report)
    coverage_incomplete = coverage.get("coverage_state") == "incomplete" or scan_run.outcome is not ScanOutcome.COMPLETE

    ecosystem_pkgs, ecosystem_servers, seen_pkgs, cred_map, total_cred_servers = _posture_inventory(report)

    all_cve, policy_findings, sev_counts, vex_suppressed_count = _posture_severity(report)

    posture, border_style = _posture_headline(report, scan_run.outcome, coverage_incomplete, policy_findings, sev_counts)

    # Build the panel content
    lines: list[str] = []
    lines.append(f"  [bold]SECURITY POSTURE:[/bold]  {posture}")
    if coverage_incomplete:
        reason = str(coverage.get("coverage_reason") or "scan coverage incomplete")
        lines.append(f"  [yellow]Coverage[/yellow]          {reason}")
    lines.append("")

    _append_posture_inventory(lines, report, ecosystem_pkgs, seen_pkgs, cred_map, total_cred_servers, vex_suppressed_count)

    _append_posture_details(lines, ecosystem_pkgs, ecosystem_servers, cred_map)

    _append_impacted_packages(lines, report, all_cve)

    _append_ai_inventory(lines, report)

    content = "\n".join(lines)
    _console().print(Panel(content, border_style=border_style, padding=(1, 1)))


def _add_ai_summary(table: Table, report: AIBOMReport) -> None:
    # AI inventory stats (if scan was run)
    ai_inv = getattr(report, "ai_inventory_data", None)
    if ai_inv and ai_inv.get("total_components", 0) > 0:
        table.add_row("AI components", str(ai_inv["total_components"]))
        shadow = ai_inv.get("shadow_ai_count", 0)
        if shadow:
            table.add_row("Shadow AI", f"[yellow]{shadow}[/yellow]")
        depr = ai_inv.get("deprecated_models_count", 0)
        if depr:
            table.add_row("Deprecated models", str(depr))
        keys = ai_inv.get("api_keys_count", 0)
        if keys:
            table.add_row("Hardcoded API keys", f"[red]{keys}[/red]")


def _add_project_summary(table: Table, report: AIBOMReport) -> None:
    project_inv = getattr(report, "project_inventory_data", None)
    if project_inv:
        table.add_row("Project manifests", str(project_inv.get("manifest_files", 0)))
        table.add_row("Lockfiles", str(project_inv.get("lockfiles", 0)))
        table.add_row(
            "Project inventory",
            (
                f"{project_inv.get('package_count', 0)} packages "
                f"({project_inv.get('direct_packages', 0)} direct / {project_inv.get('transitive_packages', 0)} transitive)"
            ),
        )
        lockfile_backed_packages = project_inv.get("lockfile_backed_packages", project_inv.get("package_count", 0))
        declaration_only_packages = project_inv.get("declaration_only_packages", 0)
        advisory_depth_pct = project_inv.get("advisory_depth_pct")
        advisory_depth = f"{lockfile_backed_packages} lockfile-backed / {declaration_only_packages} declaration-only"
        if advisory_depth_pct is not None:
            advisory_depth += f" ({advisory_depth_pct}% lockfile-backed)"
        table.add_row("Advisory depth", advisory_depth)


def _add_repo_summary(table: Table, report: AIBOMReport) -> None:
    repo_trust = getattr(report, "repo_trust_data", None)
    if isinstance(repo_trust, dict) and repo_trust:
        name = repo_trust.get("full_name") or repo_trust.get("repo_url") or "repository"
        if repo_trust.get("status") == "ok":
            bits = [str(name)]
            if repo_trust.get("stars") is not None:
                bits.append(f"★ {repo_trust['stars']}")
            if repo_trust.get("contributors") is not None:
                bits.append(f"{repo_trust['contributors']} contributors")
            if repo_trust.get("license"):
                bits.append(str(repo_trust["license"]))
            if repo_trust.get("language"):
                bits.append(str(repo_trust["language"]))
            if repo_trust.get("pushed_at"):
                bits.append(f"pushed {repo_trust['pushed_at']}")
            table.add_row("Repo trust", " · ".join(bits))
        else:
            table.add_row("Repo trust", f"{name} ({repo_trust.get('status', 'unavailable')})")


def _add_model_summary(table: Table, report: AIBOMReport) -> None:
    model_sc = getattr(report, "model_supply_chain_data", None)
    if model_sc:
        table.add_row(
            "Model artifacts",
            (
                f"{model_sc.get('model_files', 0)} file(s), "
                f"{model_sc.get('manifest_files', 0)} manifest(s), "
                f"{model_sc.get('provenance_checks', 0)} provenance check(s)"
            ),
        )
        table.add_row(
            "Model integrity",
            (
                f"{model_sc.get('signed_files', 0)} signed, "
                f"{model_sc.get('hash_verification', {}).get('verified', 0)} hash-verified, "
                f"{model_sc.get('hash_verification', {}).get('tampered', 0)} tampered"
            ),
        )
        model_lineage = model_sc.get("manifests_with_repo_id", 0) + model_sc.get("adapter_lineage_refs", 0)
        if model_lineage:
            table.add_row(
                "Model lineage",
                (f"{model_sc.get('sharded_bundles', 0)} sharded bundle(s), {model_lineage} lineage ref(s)"),
            )
        model_flags = model_sc.get("files_with_security_flags", 0) + model_sc.get("provenance_with_security_flags", 0)
        model_flags += model_sc.get("manifests_with_security_flags", 0)
        if model_flags:
            table.add_row("Model risk flags", f"[yellow]{model_flags}[/yellow]")


def _add_lookup_summary(table: Table, report: AIBOMReport) -> None:
    perf = report.scan_performance_data or {}
    osv = perf.get("osv") or {}
    registry = perf.get("registry") or {}
    advisory = perf.get("advisory_coverage") or {}
    if osv and _osv_lookup_count(osv) > 0:
        hit_rate = osv.get("cache_hit_rate_pct")
        osv_label = f"{osv.get('cache_hits', 0)} hit / {osv.get('cache_misses', 0)} miss"
        if hit_rate is not None:
            osv_label += f" ({hit_rate}% hit rate)"
        table.add_row("OSV cache", osv_label)
    if registry and _registry_lookup_count(registry) > 0:
        reg_label = f"{registry.get('cache_hits', 0)} hit / {registry.get('cache_misses', 0)} miss"
        reg_rate = registry.get("cache_hit_rate_pct")
        if reg_rate is not None:
            reg_label += f" ({reg_rate}% hit rate)"
        table.add_row("Registry cache", reg_label)
    if advisory:
        primary = advisory.get("primary_sources", {})
        enriched = advisory.get("records_with_enrichment", 0)
        primary_bits = [f"{source} {count}" for source, count in primary.items() if count]
        advisory_label = ", ".join(primary_bits) if primary_bits else "no advisory sources attributed"
        if enriched:
            advisory_label += f" · {enriched} enriched"
        table.add_row("Threat intel", advisory_label)


def _print_coverage_warnings(report: AIBOMReport) -> None:
    coverage_warnings = print_scan_notes(
        _console(), print_graph_coverage_gaps(_console(), getattr(report, "coverage_warnings", None) or [])
    )
    if coverage_warnings:

        def _coverage_line(w: dict) -> str:
            if w.get("reason") == "manifest_parse_error":
                return (
                    f"[bold yellow]⚠ {w.get('release', '?')}[/bold yellow] — "
                    f"{w.get('detail') or 'manifest failed to parse; ecosystem not scanned'}"
                )
            return (
                f"[bold yellow]⚠ {w.get('release', '?')}[/bold yellow] — "
                f"{w.get('package_count', 0)} package(s) present, "
                f"{w.get('advisory_rows', 0)} advisory row(s) in the data source"
            )

        body = "\n".join(_coverage_line(w) for w in coverage_warnings) + (
            "\n\n[dim]Vulnerability coverage for the release(s) above is incomplete — likely "
            "end-of-life and no longer carried by the data source. Results may UNDER-report; a "
            "low or zero count is NOT a clean bill of health.[/dim]"
        )
        _console().print(
            Panel.fit(
                body,
                title="[bold red]Incomplete vulnerability coverage[/bold red]",
                border_style="red",
            )
        )


def _posture_inventory(report: AIBOMReport) -> tuple[Counter[str], Counter[str], set[str], dict[str, list[str]], int]:
    # Aggregate ecosystem breakdown
    ecosystem_pkgs: Counter[str] = Counter()
    ecosystem_servers: Counter[str] = Counter()
    seen_pkgs: set[str] = set()
    for agent in report.agents:
        for server in agent.mcp_servers:
            server_ecosystems: set[str] = set()
            for pkg in server.packages:
                pkg_key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if pkg_key not in seen_pkgs:
                    seen_pkgs.add(pkg_key)
                    ecosystem_pkgs[pkg.ecosystem] += 1
                server_ecosystems.add(pkg.ecosystem)
            for eco in server_ecosystems:
                ecosystem_servers[eco] += 1

    # Aggregate credentials across agents
    cred_map: dict[str, list[str]] = {}  # cred_name → [agent names]
    total_cred_servers = 0
    for agent in report.agents:
        for server in agent.mcp_servers:
            if server.has_credentials:
                total_cred_servers += 1
                for cred in server.credential_names:
                    cred_map.setdefault(cred, []).append(f"{agent.name}/{server.name}")
    return ecosystem_pkgs, ecosystem_servers, seen_pkgs, cred_map, total_cred_servers


def _posture_severity(report: AIBOMReport) -> tuple[list[Finding], list[Finding], Counter[str], int]:
    sev_counts: Counter[str] = Counter()
    # Legacy export views may include malicious packages when there are no
    # blast-radius rows. They belong to the non-CVE pass below, exactly once.
    all_cve = [finding for finding in cve_findings(report) if finding.finding_type == FindingType.CVE]
    active_findings = [finding for finding in active_cve_findings(report) if finding.finding_type == FindingType.CVE]
    vex_suppressed_count = len(all_cve) - len(active_findings)
    for finding in active_findings:
        sev_counts[finding_severity(finding).value.upper()] += 1

    # Non-CVE policy/security findings (cloud CIS FAILs, MCP blocklist, toxic
    # combinations, governance) drive the headline too. A cloud scan with HIGH
    # CIS failures must NOT read CLEAN just because no package CVEs were found —
    # these findings already flow into to_findings() and --fail-on-severity.
    policy_findings = [finding for finding in report.to_findings() if finding.finding_type != FindingType.CVE]
    for finding in policy_findings:
        sev_counts[str(finding.severity).upper()] += 1
    return all_cve, policy_findings, sev_counts, vex_suppressed_count


def _posture_headline(
    report: AIBOMReport, outcome: ScanOutcome, coverage_incomplete: bool, policy_findings: list[Finding], sev_counts: Counter[str]
) -> tuple[str, str]:
    # Posture headline
    if outcome is ScanOutcome.FAILED:
        posture = "[bold red]SCAN FAILED[/bold red]"
        border_style = "red"
    elif coverage_incomplete:
        posture = "[bold yellow]PARTIAL COVERAGE[/bold yellow]"
        border_style = "yellow"
    elif report.total_vulnerabilities == 0 and not policy_findings:
        border_style, label = finding_free_posture(report)
        posture = f"[bold {border_style}]{label}[/bold {border_style}]"
    elif sev_counts.get("CRITICAL", 0) > 0:
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(sev, 0) > 0:
                parts.append(f"{sev_counts[sev]} {sev}")
        posture = "[bold red]" + ", ".join(parts) + "[/bold red]"
        border_style = "red"
    else:
        parts = []
        for sev in ("HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(sev, 0) > 0:
                parts.append(f"{sev_counts[sev]} {sev}")
        posture = "[bold yellow]" + ", ".join(parts) + "[/bold yellow]"
        border_style = "yellow"
    return posture, border_style


def _append_posture_inventory(
    lines: list[str],
    report: AIBOMReport,
    ecosystem_pkgs: Counter[str],
    seen_pkgs: set[str],
    cred_map: dict[str, list[str]],
    total_cred_servers: int,
    vex_suppressed_count: int,
) -> None:
    # Aggregate agent status counts
    configured = sum(1 for a in report.agents if a.status == AgentStatus.CONFIGURED)
    not_configured = sum(1 for a in report.agents if a.status == AgentStatus.INSTALLED_NOT_CONFIGURED)

    # Agent summary
    agent_parts = [f"{report.total_agents}"]
    if configured:
        agent_parts.append(f"{configured} configured")
    if not_configured:
        agent_parts.append(f"{not_configured} installed-not-configured")
    lines.append(f"  [bold]Agents[/bold]           {', '.join(agent_parts)}")

    # Server summary
    configured_agents = [a for a in report.agents if a.status == AgentStatus.CONFIGURED]
    hosting_agents = sum(1 for a in configured_agents if a.mcp_servers)
    lines.append(f"  [bold]MCP Servers[/bold]       {report.total_servers} across {hosting_agents} agent(s)")

    # Package summary with ecosystem breakdown
    unique_pkgs = len(seen_pkgs)
    if ecosystem_pkgs:
        eco_parts = [f"{eco}: {count}" for eco, count in ecosystem_pkgs.most_common()]
        lines.append(f"  [bold]Packages[/bold]          {unique_pkgs} unique ({', '.join(eco_parts)})")
    else:
        lines.append(f"  [bold]Packages[/bold]          {unique_pkgs} unique")

    # Credential exposure
    if cred_map:
        lines.append(f"  [bold yellow]Credentials[/bold yellow]       {total_cred_servers} server(s) with credentials exposed")
        cred_names = list(cred_map.keys())
        if len(cred_names) <= 4:
            lines.append(f"                    [yellow]{', '.join(cred_names)}[/yellow]")
        else:
            lines.append(f"                    [yellow]{', '.join(cred_names[:4])}[/yellow]")
            lines.append(f"                    [dim]+{len(cred_names) - 4} more[/dim]")
    else:
        lines.append("  [bold]Credentials[/bold]       None detected")

    # Privilege summary
    elevated_servers = sum(1 for a in report.agents for s in a.mcp_servers if s.permission_profile and s.permission_profile.is_elevated)
    if elevated_servers:
        lines.append(f"  [bold red]Privileges[/bold red]        {elevated_servers} server(s) with elevated privileges")
    else:
        lines.append("  [bold]Privileges[/bold]        None elevated")

    # Vulnerability count
    vuln_label = str(report.total_vulnerabilities)
    if vex_suppressed_count:
        vuln_label += f" ({vex_suppressed_count} suppressed by VEX)"
    lines.append(f"  [bold]Vulnerabilities[/bold]   {vuln_label}")


def _append_posture_details(
    lines: list[str], ecosystem_pkgs: Counter[str], ecosystem_servers: Counter[str], cred_map: dict[str, list[str]]
) -> None:
    # Ecosystem breakdown section
    if ecosystem_pkgs:
        lines.append("")
        lines.append("  [bold]Ecosystem Breakdown[/bold]")
        for eco, count in ecosystem_pkgs.most_common():
            srv_count = ecosystem_servers.get(eco, 0)
            pkg_label = "package" if count == 1 else "packages"
            srv_label = "server instance" if srv_count == 1 else "server instances"
            lines.append(f"    {eco:<10} {count} {pkg_label} across {srv_count} {srv_label}")

    # Credential exposure detail
    if cred_map:
        lines.append("")
        lines.append("  [bold]Credential Exposure[/bold]")
        for cred, locations in sorted(cred_map.items()):
            loc_str = ", ".join(locations[:3])
            if len(locations) > 3:
                loc_str += f" +{len(locations) - 3}"
            lines.append(f"    [yellow]{cred}[/yellow]  [dim]({loc_str})[/dim]")


def _append_impacted_packages(lines: list[str], report: AIBOMReport, all_cve: list[Finding]) -> None:
    # Top impacted packages (when vulns exist)
    if cve_findings(report):
        lines.append("")
        lines.append("  [bold]Top Impacted Packages[/bold]")
        # Group vulns by package
        pkg_vulns: dict[str, dict] = {}
        for finding in all_cve:
            key = f"{package_name(finding)}@{package_version(finding)}"
            if key not in pkg_vulns:
                pkg_vulns[key] = {"eco": package_ecosystem(finding), "sevs": Counter(), "agents": set(), "kev": False}
            pkg_vulns[key]["sevs"][finding_severity(finding).value.upper()] += 1
            pkg_vulns[key]["agents"].update(finding.affected_agents)
            if finding.is_kev:
                pkg_vulns[key]["kev"] = True

        # Sort by total vuln count descending
        sorted_pkgs = sorted(pkg_vulns.items(), key=lambda x: sum(x[1]["sevs"].values()), reverse=True)
        for pkg_name, info in sorted_pkgs[:5]:
            sev_parts = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if info["sevs"].get(sev, 0) > 0:
                    sev_parts.append(f"{info['sevs'][sev]} {sev.lower()}")
            kev_flag = ", [red bold]CISA KEV[/red bold]" if info["kev"] else ""
            agents_str = ", ".join(sorted(info["agents"]))
            lines.append(f"    {pkg_name} ({info['eco']})    {', '.join(sev_parts)}{kev_flag} — affects {agents_str}")


def _append_ai_inventory(lines: list[str], report: AIBOMReport) -> None:
    # AI inventory summary (when scan was run)
    ai_inv = getattr(report, "ai_inventory_data", None)
    if ai_inv and ai_inv.get("total_components", 0) > 0:
        lines.append("")
        lines.append("  [bold]AI Component Inventory[/bold]")
        lines.append(f"    Components: {ai_inv['total_components']}  \u00b7  Files scanned: {ai_inv.get('files_scanned', 0)}")
        sdks = ai_inv.get("unique_sdks", [])
        models = ai_inv.get("unique_models", [])
        if sdks:
            sdk_str = ", ".join(sdks[:6]) + (f" +{len(sdks) - 6}" if len(sdks) > 6 else "")
            lines.append(f"    SDKs: [cyan]{sdk_str}[/cyan]")
        if models:
            model_str = ", ".join(models[:6]) + (f" +{len(models) - 6}" if len(models) > 6 else "")
            lines.append(f"    Models: [cyan]{model_str}[/cyan]")
        shadow = ai_inv.get("shadow_ai_count", 0)
        depr = ai_inv.get("deprecated_models_count", 0)
        keys = ai_inv.get("api_keys_count", 0)
        risk_parts = []
        if keys:
            risk_parts.append(f"[red]{keys} hardcoded key(s)[/red]")
        if shadow:
            risk_parts.append(f"[yellow]{shadow} shadow AI[/yellow]")
        if depr:
            risk_parts.append(f"{depr} deprecated model(s)")
        if risk_parts:
            risk_str = " \u00b7 ".join(risk_parts)
            lines.append(f"    Risks: {risk_str}")
        else:
            lines.append("    Risks: [green]none[/green]")
