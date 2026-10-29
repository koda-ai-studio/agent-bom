"""Steps 1h, 1x–1z: cloud providers, benchmarks, SaaS connectors."""

from __future__ import annotations

from typing import Any

from agent_bom.cli._terminal_sections import (
    ctx_quiet,
    ctx_verbose,
    print_lane_header,
    print_provider_discovery_result,
    stage_status,
)
from agent_bom.cli.agents._benchmark_phases import _run_aisvs_phase as _run_aisvs_phase
from agent_bom.cli.agents._benchmark_phases import _run_aws_cis_benchmark_phase as _run_aws_cis_benchmark_phase
from agent_bom.cli.agents._benchmark_phases import _run_azure_cis_benchmark_phase as _run_azure_cis_benchmark_phase
from agent_bom.cli.agents._benchmark_phases import _run_databricks_security_phase as _run_databricks_security_phase
from agent_bom.cli.agents._benchmark_phases import _run_gcp_cis_benchmark_phase as _run_gcp_cis_benchmark_phase
from agent_bom.cli.agents._benchmark_phases import _run_gpu_scan_phase as _run_gpu_scan_phase
from agent_bom.cli.agents._benchmark_phases import _run_snowflake_cis_benchmark_phase as _run_snowflake_cis_benchmark_phase
from agent_bom.cli.agents._benchmark_phases import _run_vector_db_scan_phase as _run_vector_db_scan_phase
from agent_bom.cli.agents._benchmark_phases import _run_verify_model_hashes_phase as _run_verify_model_hashes_phase
from agent_bom.cli.agents._benchmark_phases import _safe_error as _safe_error
from agent_bom.cli.agents._context import ScanContext

# Shared CIS status badges across every provider table. ``not_applicable`` and
# ``no_data`` are rendered as compact badges so they are never truncated in the
# width-constrained Status column, and unknown statuses fall back to their raw
# value instead of a missing cell.
_CIS_STATUS_STYLE = {
    "pass": "[green]PASS[/]",
    "fail": "[red]FAIL[/]",
    "error": "[yellow]ERR[/]",
    "no_data": "[dim]NO DATA[/]",
    "not_applicable": "[dim]N/A[/]",
}

# Width that fits the longest rendered status label (``NO DATA``) without
# clipping.
_CIS_STATUS_WIDTH = 7


def _cis_status_badge(status_value: str) -> str:
    """Render a CIS check status as a compact, never-truncated badge."""
    return _CIS_STATUS_STYLE.get(status_value, status_value)


def run_cloud_discovery(
    ctx: ScanContext,
    *,
    skill_only: bool,
    aws: bool,
    aws_region: Any,
    aws_profile: Any,
    aws_include_lambda: bool,
    aws_include_eks: bool,
    aws_include_step_functions: bool,
    aws_include_ec2: bool,
    aws_include_iam: bool,
    aws_ec2_tag: Any,
    azure_flag: bool,
    azure_subscription: Any,
    gcp_flag: bool,
    gcp_project: Any,
    coreweave_flag: bool,
    coreweave_context: Any,
    coreweave_namespace: Any,
    databricks_flag: bool,
    snowflake_flag: bool,
    snowflake_authenticator: Any,
    nebius_flag: bool,
    nebius_api_key: Any,
    nebius_project_id: Any,
    hf_flag: bool,
    hf_token: Any,
    hf_username: Any,
    hf_organization: Any,
    wandb_flag: bool,
    wandb_api_key: Any,
    wandb_entity: Any,
    wandb_project: Any,
    mlflow_flag: bool,
    mlflow_tracking_uri: Any,
    openai_flag: bool,
    openai_api_key: Any,
    openai_org_id: Any,
    ollama_flag: bool,
    ollama_host: Any,
    jira_discover: bool = False,
    jira_url: Any = None,
    jira_user: Any = None,
    jira_token: Any = None,
    servicenow_flag: bool = False,
    servicenow_instance: Any = None,
    servicenow_token: Any = None,
    slack_discover: bool = False,
    slack_bot_token: Any = None,
    **kwargs: Any,
) -> None:
    """Step 1h: cloud provider discovery + Step 1y: SaaS connector discovery + Step 1z: multi-source correlation."""
    con = ctx.con

    # Step 1h: Cloud provider discovery
    cloud_providers: list[tuple[str, dict]] = []
    if not skill_only and aws:
        aws_kwargs: dict = {"region": aws_region, "profile": aws_profile}
        # Lambda is on by default; only pass False when the operator opts out.
        if aws_include_lambda is False:
            aws_kwargs["include_lambda"] = False
        if aws_include_eks:
            aws_kwargs["include_eks"] = True
        if aws_include_step_functions:
            aws_kwargs["include_step_functions"] = True
        if aws_include_ec2:
            aws_kwargs["include_ec2"] = True
            if aws_ec2_tag and "=" in aws_ec2_tag:
                k, v = aws_ec2_tag.split("=", 1)
                aws_kwargs["ec2_tag_filter"] = {k: v}
        if aws_include_iam:
            aws_kwargs["include_iam"] = True
        cloud_providers.append(("aws", aws_kwargs))
    if not skill_only and azure_flag:
        cloud_providers.append(("azure", {"subscription_id": azure_subscription}))
    if not skill_only and gcp_flag:
        cloud_providers.append(("gcp", {"project_id": gcp_project}))
    if not skill_only and coreweave_flag:
        cloud_providers.append(("coreweave", {"context": coreweave_context, "namespace": coreweave_namespace}))
    if not skill_only and databricks_flag:
        cloud_providers.append(("databricks", {}))
    if not skill_only and snowflake_flag:
        cloud_providers.append(("snowflake", {"authenticator": snowflake_authenticator} if snowflake_authenticator else {}))
    if not skill_only and nebius_flag:
        cloud_providers.append(("nebius", {"api_key": nebius_api_key, "project_id": nebius_project_id}))
    if not skill_only and hf_flag:
        cloud_providers.append(("huggingface", {"token": hf_token, "username": hf_username, "organization": hf_organization}))
    if not skill_only and wandb_flag:
        cloud_providers.append(("wandb", {"api_key": wandb_api_key, "entity": wandb_entity, "project": wandb_project}))
    if not skill_only and mlflow_flag:
        cloud_providers.append(("mlflow", {"tracking_uri": mlflow_tracking_uri}))
    if not skill_only and openai_flag:
        cloud_providers.append(("openai", {"api_key": openai_api_key, "organization": openai_org_id}))
    if not skill_only and ollama_flag:
        cloud_providers.append(("ollama", {"host": ollama_host}))

    _pre_cloud_idx = len(ctx.agents)
    quiet = ctx_quiet(ctx)
    verbose = ctx_verbose(ctx)
    for provider_name, provider_kwargs in cloud_providers:
        from agent_bom.cloud import discover_from_provider

        if verbose and not quiet:
            print_lane_header(con, "discover", f"{provider_name.upper()} agents")
        try:
            with stage_status(con, f"[bold]Discovering {provider_name.upper()}…[/bold]", enabled=not quiet and not verbose):
                cloud_agents, cloud_warnings = discover_from_provider(provider_name, **provider_kwargs)
            if not quiet:
                pkg_count = sum(a.total_packages for a in cloud_agents) if cloud_agents else 0
                print_provider_discovery_result(
                    con,
                    provider_name,
                    agent_count=len(cloud_agents),
                    package_count=pkg_count,
                    warnings=cloud_warnings,
                    verbose=verbose,
                )
            if cloud_agents:
                ctx.agents.extend(cloud_agents)
            for warning in cloud_warnings:
                ctx.cloud_provider_warnings.append({"provider": provider_name, "stage": "discovery", "warning": str(warning)})
            if cloud_warnings and not cloud_agents:
                # Provider implementations historically returned fatal credential,
                # permission, and enumeration errors as warning strings. An empty
                # warning-bearing result is not a verified empty inventory.
                ctx.cloud_provider_failures.append(
                    {
                        "provider": provider_name,
                        "stage": "discovery",
                        "error": "Requested cloud collector did not complete.",
                    }
                )
            else:
                # Warning-bearing results that preserve some assets are successful
                # partial collections; scan_run records the incomplete coverage.
                ctx.cloud_provider_successes.append({"provider": provider_name, "stage": "discovery", "item_count": len(cloud_agents)})
        except Exception as exc:  # noqa: BLE001 - isolate requested collectors so later providers still run
            if not quiet:
                con.print(f"\n  [red]{provider_name.upper()} discovery error: {_safe_error(exc)}[/red]")
            # A requested provider whose SDK or credentials are missing/invalid is a
            # hard failure, not a clean empty result. Record it so the final exit code
            # is non-zero (silent CI passes are the bug). The loop continues, so the
            # other requested providers are still scanned.
            ctx.cloud_provider_failures.append({"provider": provider_name, "stage": "discovery", "error": _safe_error(exc)})

    # Step 1h2: Auto-scan container images discovered from cloud providers (Azure, GCP, etc.)
    # Cloud providers discover container refs but cannot scan them — bridge that gap here.
    _cloud_image_targets: list[tuple[str, Any]] = []  # (image_ref, MCPServer to populate)
    for agent in ctx.agents[_pre_cloud_idx:]:
        for server in agent.mcp_servers:
            # A ``container-image`` package is just the image name:tag placeholder
            # that ECS/EKS/SageMaker/Cloud Run pre-fill — not real dependency
            # extraction. Treat it as empty so those images still get deep-scanned
            # (Azure already works because it leaves packages empty).
            _real_pkgs = [p for p in server.packages if p.ecosystem != "container-image"]
            if server.command == "docker" and len(server.args) >= 2 and server.args[0] == "run" and not _real_pkgs:
                _cloud_image_targets.append((server.args[1], server))

    if _cloud_image_targets:
        from agent_bom.image import ImageScanError, scan_image
        from agent_bom.models import ServerSurface

        # Deduplicate: if multiple agents share the same image, scan once and share packages
        _seen: dict[str, list] = {}
        for img_ref, srv in _cloud_image_targets:
            srv.surface = ServerSurface.CONTAINER_IMAGE
            _seen.setdefault(img_ref, []).append(srv)

        if verbose and not quiet:
            print_lane_header(con, "scan", f"{len(_seen)} cloud container image(s)")
        with stage_status(con, f"[bold]Scanning {len(_seen)} cloud image(s)…[/bold]", enabled=not quiet and not verbose):
            for img_ref, servers in _seen.items():
                try:
                    img_packages, strategy = scan_image(img_ref)
                    for srv in servers:
                        srv.packages = img_packages
                    if not quiet:
                        con.print(f"  [green]✓[/green] {img_ref}: {len(img_packages)} package(s) [dim](via {strategy})[/dim]")
                except ImageScanError as exc:
                    if not quiet:
                        con.print(f"  [yellow]![/yellow] cloud image {img_ref}: {exc}")
                except Exception as exc:
                    if not quiet:
                        con.print(f"  [yellow]![/yellow] cloud image {img_ref}: could not scan — {exc}")

    # Step 1y: SaaS connector discovery
    saas_connectors: list[tuple[str, dict]] = []
    if not skill_only and jira_discover:
        saas_connectors.append(("jira", {"jira_url": jira_url, "email": jira_user, "api_token": jira_token}))
    if not skill_only and servicenow_flag:
        saas_connectors.append(("servicenow", {"instance_url": servicenow_instance, "token": servicenow_token}))
    if not skill_only and slack_discover:
        saas_connectors.append(("slack", {"bot_token": slack_bot_token}))

    for connector_name, connector_kwargs in saas_connectors:
        from agent_bom.connectors import ConnectorError, discover_from_connector

        if verbose and not quiet:
            print_lane_header(con, "discover", f"{connector_name.upper()} connector")
        try:
            with stage_status(con, f"[bold]Discovering {connector_name.upper()}…[/bold]", enabled=not quiet and not verbose):
                con_agents, con_warnings = discover_from_connector(connector_name, **connector_kwargs)
            if not quiet:
                print_provider_discovery_result(
                    con,
                    connector_name,
                    agent_count=len(con_agents),
                    package_count=0,
                    warnings=con_warnings,
                    verbose=verbose,
                )
            if con_agents:
                ctx.agents.extend(con_agents)
        except ConnectorError as exc:
            if not quiet:
                con.print(f"\n  [red]{connector_name.upper()} connector error: {exc}[/red]")

    # Step 1z: Multi-source correlation (dedup + merge across sources)
    if not skill_only and ctx.agents:
        sources = {a.source or "local" for a in ctx.agents}
        if len(sources) > 1:
            from agent_bom.correlate import correlate_agents

            ctx.agents, corr_result = correlate_agents(ctx.agents)
            if corr_result.cross_source_matches and not quiet:
                con.print(
                    f"\n  [bold]Correlated:[/bold] {corr_result.cross_source_matches} package(s) "
                    f"merged across {len(corr_result.source_summary)} source(s)"
                )


def run_benchmarks(
    ctx: ScanContext,
    *,
    skill_only: bool,
    verify_model_hashes: bool,
    project: Any,
    hf_token: Any,
    aws_cis_benchmark: bool,
    aws_region: Any,
    aws_profile: Any,
    snowflake_cis_benchmark: bool,
    snowflake_authenticator: Any,
    azure_cis_benchmark: bool,
    azure_subscription: Any,
    gcp_cis_benchmark: bool,
    gcp_project: Any,
    databricks_security: bool,
    aisvs_flag: bool,
    vector_db_scan: bool,
    gpu_scan_flag: bool,
    gpu_k8s_context: Any,
    no_dcgm_probe: bool,
    smithery_flag: bool,
    smithery_token: Any,
    mcp_registry_flag: bool,
    snyk_flag: bool,
    snyk_token: Any,
    snyk_org: Any,
    cortex_observability: bool,
    snowflake_flag: bool = False,
    **kwargs: Any,
) -> None:
    """Steps 1x–1z: model hash, CIS benchmarks, AISVS, vector DB, GPU, SaaS connectors."""
    con = ctx.con
    quiet = ctx_quiet(ctx)
    verbose = ctx_verbose(ctx)

    # Step 1x: Model hash verification (supply chain integrity)
    if verify_model_hashes:
        _run_verify_model_hashes_phase(con, ctx, hf_token, project)

    # Step 1y: CIS AWS Foundations Benchmark
    if aws_cis_benchmark:
        _run_aws_cis_benchmark_phase(aws_profile, aws_region, con, ctx, quiet, verbose)

    # Step 1x-sf: CIS Snowflake Benchmark
    if snowflake_cis_benchmark:
        _run_snowflake_cis_benchmark_phase(con, ctx, quiet, snowflake_authenticator, verbose)

    # Step 1x-az: CIS Azure Benchmark
    if azure_cis_benchmark:
        _run_azure_cis_benchmark_phase(azure_subscription, con, ctx, quiet, verbose)

    # Step 1x-gcp: CIS GCP Benchmark
    if gcp_cis_benchmark:
        _run_gcp_cis_benchmark_phase(con, ctx, gcp_project, quiet, verbose)

    # Step 1x-db: Databricks Security Best Practices
    if databricks_security:
        _run_databricks_security_phase(con, ctx, quiet, verbose)

    # Step 1x-b: Vector DB scan
    if vector_db_scan:
        _run_vector_db_scan_phase(con, ctx)

    # Step 1x-b2: GPU infra scan
    if gpu_scan_flag:
        _run_gpu_scan_phase(con, ctx, gpu_k8s_context, no_dcgm_probe)

    # Step 1x-c: AISVS compliance benchmark
    if aisvs_flag:
        _run_aisvs_phase(con, ctx, quiet, verbose)


# click.Context.meta key the cloud command writes when --show-passed is set;
# meta is shared across the whole context stack, so it survives the
# ``cloud scan`` → ``scan`` invoke without a new flag on the scan command.
CIS_SHOW_PASSED_META = "cis_show_passed"


def render_cis_findings_from_context(ctx: ScanContext) -> None:
    """Render grouped CIS posture once at report time (not during discovery).

    Builds a lightweight report-shaped view exposing each provider's
    serialized bundle under the attribute name the renderer reads
    (``*_cis_benchmark_data``), then defers to ``print_cis_findings``.
    Honors the cloud command's ``--show-passed`` flag (carried on the click
    context ``meta``) to list passed checks instead of collapsing them.
    Emits nothing when no CIS data is present.
    """
    from types import SimpleNamespace
    from typing import cast

    import click

    from agent_bom.models import AIBOMReport
    from agent_bom.output.console_render import print_cis_findings

    bundle_attrs = (
        ("cis_benchmark_data", ctx.cis_benchmark_report),
        ("azure_cis_benchmark_data", ctx.azure_cis_benchmark_report),
        ("gcp_cis_benchmark_data", ctx.gcp_cis_benchmark_report),
        ("snowflake_cis_benchmark_data", ctx.sf_cis_benchmark_report),
        ("databricks_security_data", ctx.databricks_security_report),
    )
    # print_cis_findings reads each provider's bundle off the report via
    # getattr(report, "<provider>_cis_benchmark_data"); a namespace carrying
    # exactly those attributes is all it touches, so no full report is needed.
    view = SimpleNamespace(**{attr: (rep.to_dict() if rep is not None else None) for attr, rep in bundle_attrs})

    click_ctx = click.get_current_context(silent=True)
    show_passed = bool(click_ctx.meta.get(CIS_SHOW_PASSED_META)) if click_ctx is not None else False
    print_cis_findings(cast("AIBOMReport", view), show_passed=show_passed)
