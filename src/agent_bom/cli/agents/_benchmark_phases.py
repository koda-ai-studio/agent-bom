"""Independent optional benchmark phases for the scan command."""

from __future__ import annotations

from typing import Any

from agent_bom.cli._terminal_sections import (
    print_benchmark_line,
    print_lane_header,
    stage_status,
)
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._gpu_console import print_gpu_workload_summary
from agent_bom.core.settings import env_raw


def _run_verify_model_hashes_phase(con: Any, ctx: ScanContext, hf_token: Any, project: Any) -> None:
    from pathlib import Path

    from agent_bom.model_hash import verify_model_hashes as _verify_hashes

    _scan_roots = [Path(project)] if project else [Path.home()]
    _combined_hash_report: dict[str, Any] = {
        "scanned": 0,
        "verified": 0,
        "tampered": 0,
        "unverified": 0,
        "offline": 0,
        "has_tampering": False,
        "results": [],
        "roots": [],
    }
    for _root in _scan_roots:
        with con.status(f"[bold]Verifying model weight hashes under {_root.name}...[/bold]", spinner="dots"):
            _hash_report = _verify_hashes(str(_root), token=hf_token)
        _hash_data = _hash_report.to_dict()
        _combined_hash_report["scanned"] += _hash_data["scanned"]
        _combined_hash_report["verified"] += _hash_data["verified"]
        _combined_hash_report["tampered"] += _hash_data["tampered"]
        _combined_hash_report["unverified"] += _hash_data["unverified"]
        _combined_hash_report["offline"] += _hash_data["offline"]
        _combined_hash_report["has_tampering"] = _combined_hash_report["has_tampering"] or _hash_data["has_tampering"]
        _combined_hash_report["results"].extend(_hash_data["results"])
        _combined_hash_report["roots"].append(str(_root))
        if _hash_report.scanned == 0:
            con.print(f"  [dim]No model weight files found under {_root}[/dim]")
        elif _hash_report.has_tampering:
            con.print(
                f"  [red]⚠ SUPPLY_CHAIN_TAMPERING[/red] {_hash_report.tampered} tampered file(s) out of {_hash_report.scanned} scanned"
            )
            for r in _hash_report.results:
                if r.is_tampered:
                    con.print(
                        f"    [red]✗[/red] {r.filename}"
                        f"  expected={(r.expected_sha256 or '?')[:16]}…"
                        f"  got={r.actual_sha256[:16] if r.actual_sha256 else '?'}…"
                    )
        elif _hash_report.offline > 0:
            con.print(f"  [yellow]~[/yellow] {_hash_report.scanned} file(s) found — HuggingFace Hub unreachable, hashes unverified")
        else:
            con.print(
                f"  [green]✓[/green] {_hash_report.verified} model file(s) verified, {_hash_report.unverified} unverified (not in Hub)"
            )
    ctx.model_hash_verification_data = _combined_hash_report


def _run_aws_cis_benchmark_phase(aws_profile: Any, aws_region: Any, con: Any, ctx: ScanContext, quiet: Any, verbose: Any) -> None:
    from agent_bom.cloud import CloudDiscoveryError

    if verbose and not quiet:
        print_lane_header(con, "govern", "CIS AWS Foundations Benchmark v3.0")
    try:
        from agent_bom.cloud import aws_organizations

        with stage_status(con, "[bold]CIS AWS Foundations Benchmark v3.0[/bold]", enabled=not quiet and not verbose):
            # When the org fan-out flag is on, fan the benchmark across every
            # member account of the organization (same boundary set the inventory
            # fan-out uses) and aggregate with per-account attribution. Each
            # account is reached via a read-only AssumeRole; an account that denies
            # the role is skipped. Off keeps one account while still
            # enumerating all enabled regions for account-wide CIS truth.
            if aws_organizations.org_fanout_enabled():
                from agent_bom.cloud.aws_cis_benchmark import run_all_account_benchmarks

                ctx.cis_benchmark_report = run_all_account_benchmarks(profile=aws_profile)
            else:
                from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_cis
                from agent_bom.cloud.aws_cis_benchmark import run_benchmark_all_regions

                # CIS is an estate benchmark: enumerate every enabled
                # region by default so a quiet home region cannot produce
                # an account-wide PASS while resources exist elsewhere.
                # An explicit region remains a deliberate partial scope.
                if aws_region:
                    ctx.cis_benchmark_report = run_cis(profile=aws_profile, region=aws_region)
                else:
                    ctx.cis_benchmark_report = run_benchmark_all_regions(profile=aws_profile)
        passed = ctx.cis_benchmark_report.passed
        failed = ctx.cis_benchmark_report.failed
        total = ctx.cis_benchmark_report.total
        rate = ctx.cis_benchmark_report.pass_rate
        errored = getattr(ctx.cis_benchmark_report, "errored", 0)
        scanned = getattr(ctx.cis_benchmark_report, "accounts_scanned", []) or []
        regions_scanned = getattr(ctx.cis_benchmark_report, "regions_scanned", []) or []
        completeness = str(getattr(ctx.cis_benchmark_report, "completeness", "partial") or "partial")
        scope = f"{len(scanned)} account(s)" if len(scanned) > 1 else ""
        if len(regions_scanned) > 1:
            scope = f"{len(regions_scanned)} region(s)" if not scope else f"{scope}, {len(regions_scanned)} region(s)"
        if completeness != "complete":
            scope = f"{completeness} evidence" if not scope else f"{scope}, {completeness} evidence"
        if not quiet:
            print_benchmark_line(
                con,
                "CIS AWS",
                total=total,
                passed=passed,
                failed=failed,
                pass_rate=rate,
                scope=scope,
                errored=errored,
            )
    except CloudDiscoveryError as exc:
        if not quiet:
            con.print(f"  [red]CIS Benchmark error: {_safe_error(exc)}[/red]")
        ctx.cloud_provider_failures.append({"provider": "aws", "stage": "cis_benchmark", "error": str(exc)})


def _run_snowflake_cis_benchmark_phase(con: Any, ctx: ScanContext, quiet: Any, snowflake_authenticator: Any, verbose: Any) -> None:
    from agent_bom.cloud import CloudDiscoveryError as _SFCISError

    if verbose and not quiet:
        print_lane_header(con, "govern", "CIS Snowflake Benchmark v1.0")
    try:
        from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_sf_cis

        with stage_status(con, "[bold]CIS Snowflake Benchmark v1.0[/bold]", enabled=not quiet and not verbose):
            # Forward the chosen authenticator; account/user resolve from env.
            ctx.sf_cis_benchmark_report = run_sf_cis(authenticator=snowflake_authenticator or None)
        passed = ctx.sf_cis_benchmark_report.passed
        failed = ctx.sf_cis_benchmark_report.failed
        total = ctx.sf_cis_benchmark_report.total
        rate = ctx.sf_cis_benchmark_report.pass_rate
        if not quiet:
            print_benchmark_line(con, "CIS Snowflake", total=total, passed=passed, failed=failed, pass_rate=rate)
    except _SFCISError as exc:
        if not quiet:
            con.print(f"  [red]CIS Snowflake Benchmark error: {_safe_error(exc)}[/red]")
        ctx.cloud_provider_failures.append({"provider": "snowflake", "stage": "cis_benchmark", "error": str(exc)})


def _run_azure_cis_benchmark_phase(azure_subscription: Any, con: Any, ctx: ScanContext, quiet: Any, verbose: Any) -> None:
    from agent_bom.cloud import CloudDiscoveryError as _AZCISError

    if verbose and not quiet:
        print_lane_header(con, "govern", "CIS Azure Security Benchmark v3.0")
    try:
        from agent_bom.cloud import azure_inventory

        with stage_status(con, "[bold]CIS Azure Security Benchmark v3.0[/bold]", enabled=not quiet and not verbose):
            # When the multi-subscription flag is on, fan the benchmark across
            # every subscription in the tenant (same boundary set the inventory
            # fan-out uses) and aggregate with per-subscription attribution.
            # Off = unchanged single-subscription run.
            if azure_inventory.all_subscriptions_enabled():
                from agent_bom.cloud.azure_cis_benchmark import run_all_subscription_benchmarks

                ctx.azure_cis_benchmark_report = run_all_subscription_benchmarks()
            else:
                from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_az_cis

                # Forward the --subscription value; run_benchmark falls back to
                # AZURE_SUBSCRIPTION_ID only when this is None.
                ctx.azure_cis_benchmark_report = run_az_cis(subscription_id=azure_subscription or None)
        passed = ctx.azure_cis_benchmark_report.passed
        failed = ctx.azure_cis_benchmark_report.failed
        total = ctx.azure_cis_benchmark_report.total
        rate = ctx.azure_cis_benchmark_report.pass_rate
        errored = getattr(ctx.azure_cis_benchmark_report, "errored", 0)
        scanned = getattr(ctx.azure_cis_benchmark_report, "subscriptions_scanned", []) or []
        scope = f"{len(scanned)} subscription(s)" if len(scanned) > 1 else ""
        if not quiet:
            print_benchmark_line(
                con,
                "CIS Azure",
                total=total,
                passed=passed,
                failed=failed,
                pass_rate=rate,
                scope=scope,
                errored=errored,
            )
    except _AZCISError as exc:
        if not quiet:
            con.print(f"  [red]CIS Azure Benchmark error: {_safe_error(exc)}[/red]")
        ctx.cloud_provider_failures.append({"provider": "azure", "stage": "cis_benchmark", "error": str(exc)})


def _run_gcp_cis_benchmark_phase(con: Any, ctx: ScanContext, gcp_project: Any, quiet: Any, verbose: Any) -> None:
    from agent_bom.cloud import CloudDiscoveryError as _GCPCISError

    if verbose and not quiet:
        print_lane_header(con, "govern", "CIS GCP Foundation Benchmark v3.0")
    try:
        from agent_bom.cloud import gcp_inventory

        with stage_status(con, "[bold]CIS GCP Foundation Benchmark v3.0[/bold]", enabled=not quiet and not verbose):
            # When the multi-project flag is on, fan the benchmark across every
            # project in the org/folder tree (same boundary set the inventory
            # fan-out uses) and aggregate with per-project attribution.
            # Off = unchanged single-project run.
            if gcp_inventory.all_projects_enabled():
                from agent_bom.cloud.gcp_cis_benchmark import run_all_project_benchmarks

                ctx.gcp_cis_benchmark_report = run_all_project_benchmarks()
            else:
                from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis

                ctx.gcp_cis_benchmark_report = run_gcp_cis(project_id=gcp_project or None)
        passed = ctx.gcp_cis_benchmark_report.passed
        failed = ctx.gcp_cis_benchmark_report.failed
        total = ctx.gcp_cis_benchmark_report.total
        rate = ctx.gcp_cis_benchmark_report.pass_rate
        errored = getattr(ctx.gcp_cis_benchmark_report, "errored", 0)
        scanned = getattr(ctx.gcp_cis_benchmark_report, "projects_scanned", []) or []
        scope = f"{len(scanned)} project(s)" if len(scanned) > 1 else ""
        if not quiet:
            print_benchmark_line(
                con,
                "CIS GCP",
                total=total,
                passed=passed,
                failed=failed,
                pass_rate=rate,
                scope=scope,
                errored=errored,
            )
    except _GCPCISError as exc:
        if not quiet:
            con.print(f"  [red]CIS GCP Benchmark error: {_safe_error(exc)}[/red]")
        ctx.cloud_provider_failures.append({"provider": "gcp", "stage": "cis_benchmark", "error": str(exc)})


def _run_databricks_security_phase(con: Any, ctx: ScanContext, quiet: Any, verbose: Any) -> None:
    from agent_bom.cloud import CloudDiscoveryError as _DBSecError

    if verbose and not quiet:
        print_lane_header(con, "govern", "Databricks Security Best Practices")
    try:
        from agent_bom.cloud.databricks_security import run_security_checks as run_db_sec

        with stage_status(con, "[bold]Databricks security checks[/bold]", enabled=not quiet and not verbose):
            _db_host = env_raw("DATABRICKS_HOST")
            _db_token = env_raw("DATABRICKS_TOKEN")
            ctx.databricks_security_report = run_db_sec(host=_db_host, token=_db_token)
        passed = ctx.databricks_security_report.passed
        failed = ctx.databricks_security_report.failed
        total = ctx.databricks_security_report.total
        rate = ctx.databricks_security_report.pass_rate
        if not quiet:
            print_benchmark_line(con, "Databricks", total=total, passed=passed, failed=failed, pass_rate=rate)
    except _DBSecError as exc:
        if not quiet:
            con.print(f"  [red]Databricks security check error: {_safe_error(exc)}[/red]")
        ctx.cloud_provider_failures.append({"provider": "databricks", "stage": "security_checks", "error": str(exc)})


def _run_vector_db_scan_phase(con: Any, ctx: ScanContext) -> None:
    from rich.table import Table as _RTable

    con.print("\n[bold blue]Scanning for vector databases...[/bold blue]\n")
    try:
        from agent_bom.cloud.vector_db import discover_pinecone, discover_vector_dbs

        vector_db_results = discover_vector_dbs()
        pinecone_results = discover_pinecone()
        ctx.vector_db_results = [*vector_db_results, *pinecone_results]
        if not vector_db_results and not pinecone_results:
            con.print("  [dim]No running vector databases found. Set PINECONE_API_KEY to scan Pinecone.[/dim]")
        else:
            total = len(vector_db_results) + len(pinecone_results)
            con.print(f"  Found [bold]{total}[/bold] vector database(s)")
            tbl = _RTable(title="Vector DB Security", show_lines=True)
            tbl.add_column("DB", width=10)
            tbl.add_column("Instance", width=20)
            tbl.add_column("Auth", width=8)
            tbl.add_column("Risk", width=10)
            tbl.add_column("Flags")
            _vdb_risk = {
                "critical": "[red]critical[/]",
                "high": "[bright_red]high[/]",
                "medium": "[yellow]medium[/]",
                "safe": "[green]safe[/]",
            }
            for vdb_r in vector_db_results:
                tbl.add_row(
                    vdb_r.db_type,
                    f"{vdb_r.host}:{vdb_r.port}",
                    "[green]yes[/]" if vdb_r.requires_auth else "[red]NO[/]",
                    _vdb_risk.get(vdb_r.risk_level, vdb_r.risk_level),
                    ", ".join(vdb_r.risk_flags) or "-",
                )
            for pine_r in pinecone_results:
                tbl.add_row(
                    "pinecone",
                    pine_r.index_name,
                    "[green]API key[/]",
                    _vdb_risk.get(pine_r.risk_level, pine_r.risk_level),
                    ", ".join(pine_r.risk_flags) or "-",
                )
            con.print()
            con.print(tbl)
    except Exception as exc:
        con.print(f"  [red]Vector DB scan error: {exc}[/red]")


def _run_gpu_scan_phase(con: Any, ctx: ScanContext, gpu_k8s_context: Any, no_dcgm_probe: Any) -> None:
    import asyncio as _asyncio

    from rich.table import Table as _RTable

    con.print("\n[bold blue]Scanning GPU/AI compute infrastructure...[/bold blue]\n")
    try:
        from agent_bom.cloud.gpu_infra import gpu_infra_to_agents, scan_gpu_infra

        with con.status("[bold]Probing Docker, K8s, and DCGM endpoints...[/bold]", spinner="dots"):
            ctx.gpu_infra_report = _asyncio.run(scan_gpu_infra(k8s_context=gpu_k8s_context, probe_dcgm=not no_dcgm_probe))
        for w in ctx.gpu_infra_report.warnings:
            con.print(f"  [yellow]⚠[/yellow] {w}")
        gpu_agents = gpu_infra_to_agents(ctx.gpu_infra_report)
        if gpu_agents:
            ctx.agents.extend(gpu_agents)
            con.print(
                f"  [green]✓[/green] {ctx.gpu_infra_report.total_gpu_containers} GPU container(s), "
                f"{len(ctx.gpu_infra_report.gpu_nodes)} K8s GPU node(s)"
            )
            print_gpu_workload_summary(con, ctx.gpu_infra_report)
            if ctx.gpu_infra_report.unauthenticated_dcgm_count:
                con.print(
                    f"  [red]⚠ {ctx.gpu_infra_report.unauthenticated_dcgm_count} unauthenticated DCGM exporter(s) — metrics leak[/red]"
                )
            if ctx.gpu_infra_report.dcgm_endpoints:
                tbl = _RTable(title="DCGM Endpoints", show_lines=False)
                tbl.add_column("Host", width=20)
                tbl.add_column("Port", width=8)
                tbl.add_column("Auth", width=8)
                tbl.add_column("GPUs", width=6)
                for ep in ctx.gpu_infra_report.dcgm_endpoints:
                    tbl.add_row(
                        ep.host,
                        str(ep.port),
                        "[green]yes[/]" if ep.authenticated else "[red]NO[/]",
                        str(ep.gpu_count) if ep.gpu_count is not None else "?",
                    )
                con.print()
                con.print(tbl)
        else:
            con.print("  [dim]No GPU containers or K8s GPU nodes found[/dim]")
    except Exception as exc:
        con.print(f"  [red]GPU scan error: {exc}[/red]")


def _run_aisvs_phase(con: Any, ctx: ScanContext, quiet: Any, verbose: Any) -> None:
    from rich.table import Table as _RTable

    if verbose and not quiet:
        print_lane_header(con, "govern", "AISVS v1.0 compliance")
    try:
        from agent_bom.cloud.aisvs_benchmark import run_benchmark as _run_aisvs

        with stage_status(con, "[bold]AISVS v1.0 compliance[/bold]", enabled=not quiet and not verbose):
            ctx.aisvs_report = _run_aisvs()
        passed = ctx.aisvs_report.passed
        failed = ctx.aisvs_report.failed
        total = ctx.aisvs_report.total
        rate = ctx.aisvs_report.pass_rate
        if not quiet:
            print_benchmark_line(con, "AISVS", total=total, passed=passed, failed=failed, pass_rate=rate)
        if verbose and not quiet:
            tbl = _RTable(title="AISVS Compliance", show_lines=True)
            tbl.add_column("Check", width=8)
            tbl.add_column("Title", max_width=45)
            tbl.add_column("Status", width=8)
            tbl.add_column("Sev", width=8)
            tbl.add_column("MAESTRO", width=22)
            tbl.add_column("Evidence", max_width=40)
            _aiv_status = {
                "pass": "[green]PASS[/]",
                "fail": "[red]FAIL[/]",
                "error": "[yellow]ERR[/]",
                "not_applicable": "[dim]N/A[/]",
            }
            from agent_bom.maestro import tag_aisvs_check as _maestro_tag

            for c in ctx.aisvs_report.checks:
                maestro = _maestro_tag(c.check_id).value
                tbl.add_row(
                    c.check_id,
                    c.title,
                    _aiv_status.get(c.status.value, c.status.value),
                    c.severity,
                    maestro,
                    c.evidence,
                )
            con.print()
            con.print(tbl)
    except Exception as exc:
        if not quiet:
            con.print(f"  [red]AISVS benchmark error: {exc}[/red]")


def _safe_error(exc: object) -> str:
    """Escape an error message for Rich so bracketed install hints survive.

    Provider errors carry hints like ``pip install 'agent-bom[aws]'``; without
    escaping, Rich parses ``[aws]`` as a markup tag and drops it, mangling the
    one piece of guidance the operator needs.
    """
    from rich.markup import escape

    return escape(str(exc))
