"""Staged implementation of ``agent-bom check``.

``run_check`` runs ``CHECK_STAGES`` in order over one mutable ``CheckRun``.
Every stage either returns (the next stage runs) or ends the command with
``sys.exit`` carrying the documented exit code (0 clean, 1 unsafe/malicious,
2 incomplete).
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from functools import partial
from typing import Any, Optional

import click
from rich.console import Console

from agent_bom import vuln_freshness
from agent_bom.cli import _check_published
from agent_bom.cli._check_candidates import print_candidates
from agent_bom.cli._check_support import (
    _check_result_payload,
    _emit,
    _format_vulnerability_count,
    _package_spec_error,
    _parse_package_spec,
    _resolve_check_ecosystems,
    _vulnerability_row,
    _vulns_at_or_above,
)
from agent_bom.cli._common import _sync_runtime_consoles
from agent_bom.resolvers.latest_stable import PRERELEASE_NOTE, PRERELEASE_VERSION_SOURCE, resolved_version_source
from agent_bom.vuln_freshness import db_stale_days_threshold, db_staleness, set_allow_stale_db


@dataclass
class CheckRun:
    """Options plus the values each stage hands to the next."""

    package_spec: str
    ecosystem: Optional[str]
    quiet: bool
    no_color: bool
    output_format: str
    output_path: str | None
    exit_zero: bool
    enrich: bool
    offline: bool
    fail_on_severity: str | None
    nvd_api_key: str | None
    allow_stale_db: bool = False
    require_fresh_db: bool = False
    agent_mode: bool = False
    structured_output: bool = False
    console: Any = None
    result_payload: Callable[..., dict] = _check_result_payload
    name: str = ""
    version: str = ""
    version_source: str = "requested"
    detected_eco: str = ""
    ecosystems: list[str] = field(default_factory=list)
    pkgs: list[Any] = field(default_factory=list)
    os_context_complete: bool = True
    eco_display: str = ""
    scan_warnings: list[Any] = field(default_factory=list)
    offline_coverage_gap: bool = False
    remote_lookup_gap: bool = False
    package_version_gap: bool = False
    distro_release_gap: bool = False
    matched_pkg: Any = None
    vulns: list[Any] = field(default_factory=list)
    fail_threshold: str | None = None
    data_evidence: Any = None


def _prepare(ctx: click.Context, run: CheckRun) -> None:
    from agent_bom.cli._agent_mode import agent_mode_requested

    parent_params = getattr(getattr(ctx, "parent", None), "params", {}) or {}
    root_params = getattr(ctx.find_root(), "params", {}) or {}
    run.agent_mode = bool(parent_params.get("agent_mode") or root_params.get("agent_mode") or agent_mode_requested())
    run.output_format = run.output_format.lower()
    if run.output_path and run.output_format not in {"json", "sarif"}:
        raise click.ClickException("`check --output` requires `--format json` or `--format sarif`.")
    if run.agent_mode and run.output_format == "sarif":
        raise click.ClickException("--agent-mode requires `--format json`.")
    run.structured_output = run.output_format in {"json", "sarif"} or run.agent_mode
    run.console = Console(no_color=run.no_color, stderr=run.structured_output or run.output_path is not None)
    runtime_console = Console(
        stderr=True,
        quiet=run.quiet or run.structured_output or run.output_path is not None,
        no_color=run.no_color,
    )
    _sync_runtime_consoles(runtime_console)
    run.result_payload = partial(_check_result_payload, lookup_mode="offline" if run.offline else "online")

    run.name, run.version, run.detected_eco = _parse_package_spec(run.package_spec, run.ecosystem)


def _reject_invalid_spec(run: CheckRun) -> None:
    package_error = _package_spec_error(run.name, run.detected_eco)
    if package_error:
        if run.structured_output:
            _emit(run, ecosystems=[run.detected_eco], verdict="incomplete", message=package_error, exit_code=2)
        else:
            raise click.UsageError(package_error)
        sys.exit(2)


def _reject_missing_version(run: CheckRun) -> None:
    if run.version == "unknown" and not run.offline and run.detected_eco not in {"deb", "apk", "rpm"}:
        # Like the MCP check tool: no version means the latest published one.
        run.version = "latest"
        return
    if run.version == "unknown":
        # Without a version we cannot query OSV, so NOTHING was actually
        # checked. This is an incomplete scan, not a clean pass — exit
        # non-zero (rc=2) so a CI pre-install gate does not treat an
        # unscanned package as safe.
        message = f"No version specified for {run.name}; skipping OSV lookup."
        if run.structured_output:
            _emit(run, ecosystems=[run.detected_eco], verdict="skipped", message=message, exit_code=2)
        else:
            # Route the skip notice to stderr with a loud WARNING banner so it
            # is not mistaken for a clean result. Without a version we cannot
            # query OSV, so NOTHING was actually checked — that must be
            # unmistakable even when stdout is piped or scanned by a wrapper.
            warn_console = Console(stderr=True, no_color=run.no_color)
            warn_console.print(
                f"[bold yellow]⚠ WARNING: no version given for '{run.name}' — NOT scanned (OSV lookup skipped).[/bold yellow]"
            )
            warn_console.print(f"  This is not a clean result. Re-run with a version: agent-bom check {run.name}@<version>")
        sys.exit(2)


def _build_packages(run: CheckRun) -> None:
    from agent_bom.models import Package
    from agent_bom.parsers.os_parsers import enrich_os_package_context

    run.ecosystems = _resolve_check_ecosystems(run.name, run.version, run.ecosystem, run.detected_eco)
    run.pkgs = [Package(name=run.name, version=run.version, ecosystem=eco) for eco in run.ecosystems]
    run.version = run.pkgs[0].version
    run.os_context_complete = True
    for pkg in run.pkgs:
        if pkg.ecosystem in {"deb", "apk", "rpm"}:
            run.os_context_complete = enrich_os_package_context(pkg) and run.os_context_complete


def _resolve_latest(run: CheckRun) -> None:
    """Check the latest published version when none was given; never guess one."""
    if run.version not in ("latest", ""):
        return
    status = nullcontext() if run.quiet else run.console.status("[bold]Resolving version from registry...[/bold]", spinner="dots")
    with status:
        resolved, malicious_reason = _check_published.resolve_latest(run.pkgs)
    if resolved is not None:
        run.version = resolved.version
        run.version_source = resolved_version_source(resolved.version_source)
        for p in run.pkgs:
            p.version = run.version
        if not run.quiet and not run.structured_output:
            note = f" ({PRERELEASE_NOTE})" if run.version_source == PRERELEASE_VERSION_SOURCE else ""
            run.console.print(f"  [green]✓ No version given; checking the latest published version, {run.version}{note}[/green]")
        return
    # Nothing resolved: the payload must not read as a requested version of "latest".
    run.version_source = "unresolved"
    eco_str = "/".join(run.ecosystems)
    if malicious_reason:
        run.pkgs[0].is_malicious, run.pkgs[0].malicious_reason = True, malicious_reason
        _gate_malicious(run)
    message = f"Could not resolve the latest published version of {run.name} ({eco_str}); nothing was checked. Provide an explicit version."
    if run.structured_output:
        _emit(run, ecosystems=run.ecosystems, verdict="incomplete", message=message, exit_code=2)
    else:
        run.console.print(f"[yellow]⚠ {message}[/yellow]")
        run.console.print("  For example: agent-bom check name@1.2.3 -e ecosystem")
    sys.exit(2)


def _scan(run: CheckRun) -> None:
    run.eco_display = "/".join(run.ecosystems)
    if not run.quiet and not run.structured_output:
        run.console.print(f"\n[bold blue]🔍 Checking {run.name}@{run.version} ({run.eco_display})[/bold blue]\n")

    status_context: Any
    if not run.quiet and not run.structured_output:
        status_context = run.console.status("[bold]Scanning package risk...[/bold]", spinner="dots")
    else:
        status_context = nullcontext()

    with status_context:
        from agent_bom.scanners import (
            IncompleteScanError,
            ScanOptions,
            consume_coverage_warnings,
            consume_scan_warnings,
            reset_scan_warnings,
            scan_packages,
        )

        # A CLI invocation owns a fresh warning boundary. Long-lived callers
        # and tests can invoke Click commands repeatedly in one process, while
        # scanner warnings are thread-local and otherwise survive until they
        # are consumed. Clear prior state before calling the replaceable scan
        # implementation so an earlier partial scan cannot turn this clean
        # offline verdict into an unrelated incomplete result.
        reset_scan_warnings()
        try:
            asyncio.run(scan_packages(run.pkgs, options=ScanOptions(offline=run.offline)))
        except IncompleteScanError as exc:
            if run.structured_output:
                _emit(run, ecosystems=run.ecosystems, verdict="incomplete", message=str(exc), exit_code=2)
            else:
                run.console.print(f"  [yellow]⚠[/yellow] {exc}")
            sys.exit(2)

    run.scan_warnings = consume_scan_warnings()
    coverage_warnings = consume_coverage_warnings()
    run.package_version_gap = any(w.get("kind") == "package_version_gap" for w in coverage_warnings)
    run.distro_release_gap = any(w.get("kind") == "distro_release_gap" for w in coverage_warnings)
    run.offline_coverage_gap = run.offline and any(w.get("kind") == "offline_ecosystem_gap" for w in coverage_warnings)
    # Same failure, over the network: the local DB carried no advisories for the
    # ecosystem AND the remote lookup errored, so nothing was consulted. Exit 2
    # ("insufficient context for a trustworthy clean verdict") rather than
    # reporting a clean that no source actually supports.
    run.remote_lookup_gap = not run.offline and any(w.get("kind") == "remote_lookup_gap" for w in coverage_warnings)
    if run.scan_warnings and not run.quiet and not run.structured_output:
        run.console.print(f"  [yellow]⚠[/yellow] Scan completed with {len(run.scan_warnings)} warning(s); results may be incomplete.")
    _record_data_evidence(run, coverage_warnings)

    run.matched_pkg = next((p for p in run.pkgs if p.vulnerabilities or p.possibly_affected), run.pkgs[0])
    run.vulns = run.matched_pkg.vulnerabilities
    print_candidates(run.matched_pkg, run.console, quiet=run.quiet or run.structured_output)
    run.fail_threshold = run.fail_on_severity.lower() if run.fail_on_severity else None


def _record_data_evidence(run: CheckRun, coverage_warnings: list[dict]) -> None:
    from agent_bom.scanners.local_data_freshness import check_data_evidence

    run.data_evidence = check_data_evidence(offline=run.offline, coverage_warnings=coverage_warnings)
    if run.data_evidence.outdated and not run.quiet and not run.structured_output:
        run.console.print(f"  [yellow]⚠ {run.data_evidence.reason}[/yellow]")


def _gate_malicious(run: CheckRun) -> None:
    # ── Malicious-package gate (fail closed) ─────────────────────────────────
    # A package flagged as malicious (typosquat, dependency-confusion, or a
    # known-malicious MAL- advisory) is a BLOCK regardless of CVE rows. Reading
    # only vuln rows let such a package report "No known vulnerabilities" and
    # exit 0 — a pre-install gate must never install a malicious package, and
    # this decision is independent of --exit-zero / --fail-on-severity, which
    # only govern vulnerability triage.
    malicious_pkg = next((p for p in run.pkgs if getattr(p, "is_malicious", False)), None)
    if malicious_pkg is not None:
        reason = malicious_pkg.malicious_reason or "flagged as malicious (typosquat / dependency confusion / known-malicious advisory)"
        message = f"MALICIOUS package {malicious_pkg.name}@{malicious_pkg.version} — {reason}. Do not install."
        if run.structured_output:
            _emit(
                run,
                ecosystems=run.ecosystems,
                verdict="malicious",
                message=message,
                exit_code=1,
                vulnerabilities=run.vulns,
                warnings=run.scan_warnings,
                malicious_reason=reason,
            )
            sys.exit(1)
        if run.quiet:
            click.echo(f"{run.name}@{run.version}: MALICIOUS — {reason}")
        else:
            run.console.print(f"  [red]✗ MALICIOUS: {message}[/red]\n")
        sys.exit(1)


def _enrich(run: CheckRun) -> None:
    if run.enrich and any(pkg.vulnerabilities for pkg in run.pkgs):
        from agent_bom.enrichment import enrich_vulnerabilities

        all_vulns = [vuln for pkg in run.pkgs for vuln in pkg.vulnerabilities]
        try:
            asyncio.run(
                enrich_vulnerabilities(
                    all_vulns,
                    nvd_api_key=run.nvd_api_key,
                    enable_nvd=True,
                    enable_epss=True,
                    enable_kev=True,
                )
            )
        except Exception as exc:  # noqa: BLE001
            run.scan_warnings.append(f"External enrichment skipped: {exc}")
            if not run.quiet and not run.structured_output:
                run.console.print(f"  [yellow]⚠[/yellow] External enrichment skipped: {exc}")


def _coverage_gap_message(run: CheckRun) -> str:
    if run.distro_release_gap:
        return (
            "Distro release is unknown; advisories are possibly affected candidates. "
            "Scan the target image or filesystem with its OS metadata."
        )
    if run.package_version_gap:
        return "Package version is unresolved or invalid; supply a valid release version for a trustworthy verdict."
    if run.remote_lookup_gap:
        return (
            f"Incomplete scan for {run.name}@{run.version} ({run.eco_display}). "
            "The remote advisory lookup failed and the local vulnerability DB carries no advisories "
            "for this ecosystem, so a clean result cannot be trusted. Retry, or run "
            "`agent-bom db update` for local coverage."
        )
    return (
        f"Incomplete offline coverage for {run.name}@{run.version} ({run.eco_display}). "
        "The local vulnerability DB carries no advisories for this ecosystem, so a clean result "
        "cannot be trusted. Run `agent-bom db update` (online) for full coverage."
    )


def _gate_coverage_gap(run: CheckRun) -> None:
    if not run.vulns and (run.offline_coverage_gap or run.remote_lookup_gap or run.package_version_gap or run.distro_release_gap):
        # An offline scan of an ecosystem the local DB carries no advisories
        # for — or an online one whose remote lookup errored with the same
        # empty DB behind it — produced no vulns because nothing could be
        # matched, NOT because the package is clean. Fail closed (rc=2) so a
        # pre-install gate isn't silently green. Re-run, `agent-bom db update`
        # for coverage, or --exit-zero to force an exploratory result.
        message = _coverage_gap_message(run)
        if run.structured_output:
            _emit(run, ecosystems=run.ecosystems, verdict="incomplete", message=message, exit_code=2, warnings=run.scan_warnings)
            sys.exit(2)
        if run.quiet:
            gap_label = "incomplete scan (remote lookup failed)" if run.remote_lookup_gap else "incomplete offline coverage"
            if run.package_version_gap:
                gap_label = "incomplete package lookup"
            if run.distro_release_gap:
                gap_label = "incomplete distro release context"
            click.echo(f"{run.name}@{run.version}: {gap_label} ({run.eco_display})")
        else:
            run.console.print(f"  [yellow]⚠ {message}[/yellow]\n")
        sys.exit(2)


def _gate_require_fresh_db(run: CheckRun) -> None:
    """``--require-fresh-db`` / ``AGENT_BOM_REQUIRE_FRESH_DB``: the same exit-3 policy gate as ``scan``."""
    if not run.require_fresh_db:
        return
    stale, age = db_staleness(vuln_freshness.compute_freshness(offline=run.offline))
    if not stale:
        return
    age_text = f"{age}d old" if age is not None else "missing or undated"
    message = (
        f"Local vulnerability DB is stale ({age_text}; threshold {db_stale_days_threshold()}d) and --require-fresh-db "
        "is set. Run `agent-bom db update`."
    )
    if run.structured_output:
        _emit(run, ecosystems=run.ecosystems or [run.detected_eco], verdict="incomplete", message=message, exit_code=3)
    elif run.quiet:
        click.echo(f"{run.name}@{run.version}: stale vulnerability DB (--require-fresh-db)")
    else:
        run.console.print(f"  [red]✗ {message}[/red]\n")
    sys.exit(3)


def _gate_incomplete_data(run: CheckRun) -> None:
    """Nothing at or above the gate on untrusted local data that OSV did not back: exit 2, not a pass."""
    failing = [] if run.exit_zero else _vulns_at_or_above(run.vulns, run.fail_threshold)
    if failing or run.data_evidence is None or not run.data_evidence.blocks_clean():
        return
    message = run.data_evidence.stale_message()
    if run.structured_output:
        _emit(
            run,
            ecosystems=run.ecosystems,
            verdict="incomplete",
            message=message,
            exit_code=2,
            vulnerabilities=run.vulns,
            warnings=run.scan_warnings,
            fail_on_severity=run.fail_threshold,
            fail_on_severity_count=0,
        )
    elif run.quiet:
        click.echo(f"{run.name}@{run.version}: incomplete (outdated local vulnerability data)")
    else:
        if run.vulns:
            _render_vulnerability_table(run)
        run.console.print(f"  [yellow]⚠ Nothing at or above the gate, but results are incomplete — exiting 2. {message}[/yellow]\n")
    sys.exit(2)


def _gate_os_context(run: CheckRun) -> None:
    if not run.vulns and run.matched_pkg.ecosystem in {"deb", "apk", "rpm"} and not run.os_context_complete:
        message = (
            f"Incomplete OS package context for {run.name}@{run.version}. "
            "Best-effort matching found no vulnerabilities, but distro metadata was insufficient for a trustworthy clean verdict."
        )
        if run.structured_output:
            _emit(run, ecosystems=run.ecosystems, verdict="incomplete", message=message, exit_code=2, warnings=run.scan_warnings)
            sys.exit(2)
        if run.quiet:
            click.echo(f"{run.name}@{run.version}: incomplete OS package context")
        else:
            run.console.print(f"  [yellow]⚠ Incomplete OS package context for {run.name}@{run.version}[/yellow]")
            run.console.print(
                "  Best-effort matching found no vulnerabilities, but source/distro metadata was "
                "insufficient for a trustworthy clean verdict.\n"
            )
        sys.exit(2)


def _gate_unpublished(run: CheckRun) -> None:
    # A pin with no advisories may not exist. Confirm it is published before
    # calling it clean, as MCP ``check`` does; a removed malware package
    # (crossenv) is malicious, any other missing version is unknown (rc=2).
    if run.offline or run.vulns or run.version in ("latest", ""):
        return
    missing = _check_published.unpublished_pin(run.name, run.version, run.ecosystems)
    if missing is None:
        return
    ecosystem, malware_reason = missing
    if malware_reason:
        for pkg in run.pkgs:
            pkg.is_malicious, pkg.malicious_reason = True, malware_reason
        _gate_malicious(run)
    message = (
        f"Version {run.version} of {run.name} was not found in the {ecosystem} registry, so it cannot be confirmed "
        "free of vulnerabilities (typo or unpublished version?). agent-bom only verifies published versions."
    )
    if run.structured_output:
        _emit(run, ecosystems=run.ecosystems, verdict="unknown", message=message, exit_code=2, warnings=run.scan_warnings)
    elif run.quiet:
        click.echo(f"{run.name}@{run.version}: UNKNOWN — not published in {ecosystem}")
    else:
        run.console.print(f"  [yellow]⚠ {message}[/yellow]\n")
    sys.exit(2)


def _report_clean(run: CheckRun) -> None:
    if not run.vulns:
        if run.structured_output:
            _emit(
                run,
                ecosystems=run.ecosystems,
                verdict="clean",
                message=f"No known vulnerabilities in {run.name}@{run.version}.",
                exit_code=0,
                warnings=run.scan_warnings,
            )
            sys.exit(0)
        complete = run.data_evidence is None or run.data_evidence.complete
        if run.quiet:
            click.echo(f"{run.name}@{run.version}: CLEAN" + ("" if complete else " (results may be incomplete)"))
        elif complete:
            run.console.print(f"  [green]✓ No known vulnerabilities in {run.name}@{run.version}[/green]\n")
        else:
            run.console.print(
                f"  [yellow]⚠ No known vulnerabilities in {run.name}@{run.version}, but results may be incomplete.[/yellow]\n"
            )
        sys.exit(0)


def _render_vulnerability_table(run: CheckRun) -> None:
    if not run.quiet and not run.structured_output:
        from rich.table import Table

        from agent_bom.cwe_impact import classify_cwe_impact

        vuln_count_text = _format_vulnerability_count(len(run.vulns))
        table = Table(title=f"{run.name}@{run.version} — {vuln_count_text}")
        table.add_column("Sev", no_wrap=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("Impact", no_wrap=True, max_width=12, overflow="ellipsis")
        table.add_column("Fix", max_width=10, overflow="fold")
        table.add_column("Summary", min_width=20, max_width=48)

        for v in run.vulns:
            table.add_row(*_vulnerability_row(v, classify_cwe_impact))
        run.console.print(table)
        run.console.print()


def _verdict_exit_zero(run: CheckRun) -> None:
    if run.exit_zero:
        vulns = run.vulns
        if run.structured_output:
            count_text = _format_vulnerability_count(len(vulns))
            _emit(
                run,
                ecosystems=run.ecosystems,
                verdict="unsafe",
                message=f"{count_text} in {run.name}@{run.version}; reported without failing due to --exit-zero.",
                exit_code=0,
                vulnerabilities=vulns,
                warnings=run.scan_warnings,
                exit_zero=True,
                fail_on_severity=run.fail_threshold,
                fail_on_severity_count=len(_vulns_at_or_above(vulns, run.fail_threshold)),
            )
            sys.exit(0)
        if run.quiet:
            click.echo(f"{run.name}@{run.version}: {_format_vulnerability_count(len(vulns))} (exit-zero)")
        else:
            run.console.print(
                f"  [yellow]⚠ {_format_vulnerability_count(len(vulns))} — reported without failing due to --exit-zero.[/yellow]\n"
            )
        sys.exit(0)


def _verdict_threshold(run: CheckRun) -> None:
    vulns = run.vulns
    fail_threshold = run.fail_threshold
    failing_vulns = _vulns_at_or_above(vulns, fail_threshold)
    if fail_threshold and not failing_vulns:
        message = f"{_format_vulnerability_count(len(vulns))} in {run.name}@{run.version}; none at or above {fail_threshold}."
        if run.structured_output:
            _emit(
                run,
                ecosystems=run.ecosystems,
                verdict="unsafe",
                message=message,
                exit_code=0,
                vulnerabilities=vulns,
                warnings=run.scan_warnings,
                fail_on_severity=fail_threshold,
                fail_on_severity_count=0,
            )
            sys.exit(0)
        if run.quiet:
            click.echo(f"{run.name}@{run.version}: {_format_vulnerability_count(len(vulns))} (below {fail_threshold})")
        else:
            run.console.print(f"  [yellow]⚠ {message}[/yellow]\n")
        sys.exit(0)

    if run.structured_output:
        _emit(
            run,
            ecosystems=run.ecosystems,
            verdict="unsafe",
            message=f"{_format_vulnerability_count(len(vulns))} in {run.name}@{run.version}.",
            exit_code=1,
            vulnerabilities=vulns,
            warnings=run.scan_warnings,
            fail_on_severity=fail_threshold,
            fail_on_severity_count=len(failing_vulns),
        )
        sys.exit(1)

    if run.quiet:
        click.echo(f"{run.name}@{run.version}: {_format_vulnerability_count(len(vulns))}")
    else:
        run.console.print(f"  [red]✗ {_format_vulnerability_count(len(vulns))} — do not install without review.[/red]\n")
    sys.exit(1)


CHECK_STAGES: tuple[Callable[[CheckRun], None], ...] = (
    _reject_invalid_spec,
    _reject_missing_version,
    _build_packages,
    _gate_require_fresh_db,
    _resolve_latest,
    _scan,
    _gate_malicious,
    _enrich,
    _gate_coverage_gap,
    _gate_os_context,
    _gate_incomplete_data,
    _gate_unpublished,
    _report_clean,
    _render_vulnerability_table,
    _verdict_exit_zero,
    _verdict_threshold,
)


def run_check(ctx: click.Context, **options: Any) -> None:
    """Run ``agent-bom check`` with the click command's keyword options."""
    run = CheckRun(**options)
    set_allow_stale_db(run.allow_stale_db)
    try:
        _prepare(ctx, run)
        for stage in CHECK_STAGES:
            stage(run)
    finally:
        set_allow_stale_db(False)
