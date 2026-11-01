"""Stage 5: match the package inventory against vulnerability data."""

from __future__ import annotations

import time as _time
from types import SimpleNamespace
from typing import Any

from agent_bom.cli.agents.scan_pipeline.helpers import _agents_patchable, _exit_incomplete_scan_with_partial_summary
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.core.vex_policy import active_blast_radii
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.scanners import IncompleteScanError, consume_scan_warnings
from agent_bom.scanners.clean_verdict import no_fixable_vulnerabilities_line, suppressed_unfixed_os_findings
from agent_bom.scanners.state import peek_coverage_warnings
from agent_bom.scanners.supplied_findings import build_supplied_findings


def _scan_agents(opts: ScanOptions, st: ScanState, **scan_kwargs: Any) -> None:
    try:
        st.blast_radii = _agents_patchable("scan_agents_sync")(
            st.agents,
            enable_enrichment=opts.enrich,
            nvd_api_key=opts.nvd_api_key,
            blast_radius_depth=opts.blast_radius_depth,
            compliance_enabled=opts.compliance,
            resolve_transitive=opts.transitive,
            **scan_kwargs,
            offline=opts.offline,
            prefer_local_db=st.prefer_local_db,
            demo_advisories=opts.demo,
        )
    except IncompleteScanError as exc:
        _exit_incomplete_scan_with_partial_summary(
            st.ctx,
            agents=st.agents,
            exc=exc,
            output=opts.output,
            output_format=opts.output_format,
            no_tree=opts.no_tree,
            quiet=opts.quiet,
            no_color=opts.no_color,
            open_report=opts.open_report,
            offline_html=opts.offline_html,
            compliance_export=opts.compliance_export,
            mermaid_mode=opts.mermaid_mode,
            push_gateway=opts.push_gateway,
            otel_endpoint=opts.otel_endpoint,
            baseline=opts.baseline,
            delta_mode=opts.delta_mode,
            verbose=opts.verbose,
            exclude_unfixable=opts.exclude_unfixable,
            fixable_only=opts.fixable_only,
            posture=opts.posture,
        )


def _scan_with_progress(opts: ScanOptions, st: ScanState) -> None:
    _unique_pkgs = len({(p.name, p.version, p.ecosystem) for a in st.agents for s in a.mcp_servers for p in s.packages})
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    from agent_bom.cli._common import rich_log_handler_during_progress

    # Route ``agent_bom.scanners.*`` warnings (rate-limit retries,
    # OSV fallbacks, etc.) through Rich for the duration of the
    # spinner so log lines render *above* the live region instead
    # of punching through it. Without this the terminal stacks
    # copies of "Scanning N packages" each time a warning fires.
    with (
        rich_log_handler_during_progress(st.con),
        Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}[/bold]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.fields[phase]}[/dim]"),
            TimeElapsedColumn(),
            console=st.con,
            transient=True,
        ) as progress,
    ):
        scan_task = progress.add_task(
            f"Scanning {_unique_pkgs} packages",
            total=4,
            phase="local DB + OSV + GHSA",
        )
        progress.update(scan_task, completed=1, phase="querying vulnerability databases...")
        _scan_agents(opts, st, show_scan_banner=False)
        progress.update(scan_task, completed=3, phase="building blast radius analysis")
        progress.update(scan_task, completed=4, phase="done")


def _join_kev_catalog(opts: ScanOptions, st: ScanState) -> None:
    """Report the KEV join the scanner ran (``--enrich`` prints its own summary)."""
    if opts.enrich or not st.blast_radii:
        return
    vulns = list({id(br.vulnerability): br.vulnerability for br in st.blast_radii}.values())
    hits = sum(1 for vuln in vulns if vuln.is_kev)
    if hits:
        st.con.print(f"  [red]⚠[/red] CISA KEV: {hits} actively exploited vulnerabilit{'y' if hits == 1 else 'ies'}")
    elif any(getattr(vuln, "kev_status", None) == "unknown" for vuln in vulns):
        st.con.print("  [yellow]⚠[/yellow] CISA KEV catalog unavailable — actively exploited CVEs cannot be ruled out")


def _print_scan_verdict(opts: ScanOptions, st: ScanState, input_vulnerability_count: int) -> None:
    run = effective_scan_run(SimpleNamespace(agents=st.agents, coverage_warnings=[*st.coverage_warnings, *peek_coverage_warnings()]))
    completion = "Package scan partial" if st.scan_warnings or run.outcome is not ScanOutcome.COMPLETE else "Package scan complete"
    if st.blast_radii:
        # Don't repeat the bare finding count — the scanner already
        # printed "Found N vulnerabilities across N finding(s)" above.
        # Surface a severity breakdown here instead so the closer
        # line tells the operator something new.
        sev_counts: dict[str, int] = {}
        for br in active_blast_radii(st.blast_radii):
            # ``BlastRadius.severity`` lives on the wrapped Vulnerability,
            # not the BlastRadius dataclass itself. ``Severity(str, Enum)``
            # holds the canonical token in ``.value`` (e.g. "critical").
            # On Python 3.13 ``str(Severity.CRITICAL)`` returns
            # "Severity.CRITICAL" rather than "critical", so reach for
            # ``.value`` first and only fall through to ``str()`` for
            # plain-string severities (policy findings, mocks).
            raw_sev = getattr(br.vulnerability, "severity", None) if getattr(br, "vulnerability", None) else None
            if raw_sev is None:
                sev_key = "unknown"
            else:
                sev_value = getattr(raw_sev, "value", raw_sev)
                sev_key = str(sev_value).lower() or "unknown"
            sev_counts[sev_key] = sev_counts.get(sev_key, 0) + 1
        _sev_order = ["critical", "high", "medium", "low", "unknown"]
        _sev_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "unknown": "dim",
        }
        _sev_str = " · ".join(f"[{_sev_color[s]}]{sev_counts[s]} {s}[/{_sev_color[s]}]" for s in _sev_order if s in sev_counts)
        # Scope-labeled: this breakdown covers package CVE findings
        # only. Graph-derived findings surface after graph analysis
        # below, and the all-categories totals line reconciles both.
        st.con.print(f"  [red]⚠[/red] {completion} — package CVEs: {_sev_str}")
        from agent_bom.output.kernel_header_console import kernel_header_summary_lines

        for line in kernel_header_summary_lines(st.blast_radii):
            st.con.print(line)
    elif input_vulnerability_count:
        st.con.print(
            f"  [yellow]⚠[/yellow] {completion} — retained "
            f"{input_vulnerability_count} vulnerability record(s) supplied by the input inventory"
        )
    elif st.scan_warnings:
        st.con.print("  [yellow]⚠[/yellow] No vulnerabilities confirmed; lookup warnings limit this assessment")
    elif run.outcome is not ScanOutcome.COMPLETE:
        st.con.print("  [yellow]⚠[/yellow] No vulnerabilities confirmed; inventory or lookup coverage is incomplete")
    elif opts.offline:
        if st.unresolved:
            st.con.print(
                "  [yellow]⚠[/yellow] Offline scan complete: no known vulnerabilities found "
                "in local data, but coverage is partial for "
                f"{len(st.unresolved)} package(s) without pinned versions"
            )
        else:
            st.con.print("  [green]✓[/green] Offline scan complete: no known vulnerabilities found in local data")
    elif suppressed := suppressed_unfixed_os_findings():
        st.con.print(f"  [yellow]⚠[/yellow] {no_fixable_vulnerabilities_line(suppressed)}")
    else:
        st.con.print("  [green]✓[/green] No known vulnerabilities found")


def _print_scorecard_coverage(opts: ScanOptions, st: ScanState) -> None:
    if opts.enrich and not opts.quiet:
        unique_scorecard = {
            (p.ecosystem, p.name, p.version) for a in st.agents for s in a.mcp_servers for p in s.packages if p.scorecard_score is not None
        }
        if unique_scorecard:
            st.con.print(f"  [green]✓[/green] OpenSSF Scorecard: enriched {len(unique_scorecard)} package(s)")
        else:
            st.con.print("  [dim]  OpenSSF Scorecard: no packages with resolvable GitHub repos[/dim]")


def _run_vulnerability_scan(opts: ScanOptions, st: ScanState) -> None:
    # Step 4: Vulnerability scan
    if not opts.quiet:
        from rich.rule import Rule

        st.con.print()
        st.con.print(Rule("Vulnerability Scan", style="red"))
        st.con.print()
    st.step_t0 = _time.monotonic()
    st.blast_radii = build_supplied_findings(st.agents) if opts.no_scan else []
    if opts.no_scan:
        if not opts.quiet:
            st.con.print("  [dim]Vulnerability scanning skipped (--no-scan)[/dim]")
    elif st.total_packages == 0:
        if not opts.quiet:
            st.con.print("  [dim]No packages to scan[/dim]")
    else:
        input_vulnerability_count = sum(len(package.vulnerabilities) for package in st.all_packages)
        if not opts.quiet:
            _scan_with_progress(opts, st)
        else:
            _scan_agents(opts, st)
        st.scan_warnings = consume_scan_warnings()
        if st.scan_warnings:
            st.con.print(f"  [yellow]⚠[/yellow] Scan completed with {len(st.scan_warnings)} warning(s); results may be incomplete.")
        _join_kev_catalog(opts, st)
        _print_scan_verdict(opts, st, input_vulnerability_count)
        _print_scorecard_coverage(opts, st)


def run_matching(opts: ScanOptions, st: ScanState) -> None:
    """Match the resolved inventory against vulnerability data."""
    if opts.skill_only:
        return
    _run_vulnerability_scan(opts, st)
