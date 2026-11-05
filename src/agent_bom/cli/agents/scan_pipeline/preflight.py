"""Stage 2: vulnerability-data preflight and the early-exit modes (dry run, IaC-only)."""

from __future__ import annotations

import sys
import time as _time
from collections.abc import Callable
from pathlib import Path

import click

from agent_bom.cli._common import logger
from agent_bom.cli.agents._preflight import run_iac_only_scan
from agent_bom.cli.agents.scan_pipeline.helpers import _agents_patchable, _reset_offline_mode
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState, StopScan
from agent_bom.core.settings import env_opt
from agent_bom.db import schema as _db_schema
from agent_bom.db.sync_common import OSV_APPLICATION_ECOSYSTEMS
from agent_bom.db.sync_nvd_window import TIME_BUDGET_ENV
from agent_bom.vuln_freshness import bundled_demo_freshness, compute_freshness, osv_archive_is_full, should_refresh

# The window is walked newest first and a partial run resumes at the next refresh,
# so a short first pass keeps the most recent CVEs and is reported as partial.
COLD_START_NVD_BUDGET_SECONDS = 60.0


def _apply_offline_mode(opts: ScanOptions, st: ScanState) -> None:
    # ── Offline mode: disable all network calls ──────────────────────────────
    if opts.offline:
        from agent_bom.scanners import set_offline_mode

        set_offline_mode(True)  # Block ALL network calls (scanner + transport layer)
        click_ctx = click.get_current_context(silent=True)
        if click_ctx is not None:
            click_ctx.call_on_close(_reset_offline_mode)
        opts.auto_update_db = False
        opts.enrich = False
        opts.scorecard_flag = False
        opts.deps_dev = False
        opts.snyk_flag = False
        if not opts.quiet:
            offline_source = "bundled demo advisory DB" if opts.demo else "local vulnerability DB"
            st.con.print(f"[dim]Offline mode — {offline_source} only[/dim]")

    # ── Auto-offline: use local DB if synced recently (saves ~10s network) ──
    st.prefer_local_db = False
    if not opts.offline and not opts.no_scan and not opts.dry_run:
        try:
            import os
            import time

            from agent_bom.db.schema import DB_PATH

            if DB_PATH.exists():
                _age_days = (time.time() - os.path.getmtime(DB_PATH)) / 86400
                if _age_days <= 1:
                    st.prefer_local_db = True
                    logger.debug("Local DB is %.1f day(s) old — preferring local DB over network", _age_days)
        except Exception:
            pass  # DB not available, will use network


def _osv_ecosystems_for_refresh(opts: ScanOptions, db_path: Path) -> list[str] | None:
    """The OSV archives this refresh reads; ``None`` is the all-ecosystems archive.

    A database already holding every ecosystem stays whole: refreshing part of it
    would leave the rest aging behind coverage metadata that still claims it all.
    """
    if opts.db_osv_scope != "application" or osv_archive_is_full(db_path):
        return None
    return list(OSV_APPLICATION_ECOSYSTEMS)


def _cold_start_nvd_budget(db_path: Path) -> float | None:
    """NVD seconds for a first refresh, which must not hold up the first scan; ``None`` keeps the configured budget."""
    return None if db_path.exists() or env_opt(TIME_BUDGET_ENV) else COLD_START_NVD_BUDGET_SECONDS


def _source_timing_reporter(opts: ScanOptions, st: ScanState) -> Callable[..., None]:
    """Record each source's refresh time, and print it: a slow runner's log should say where the time went."""
    started: dict[str, float] = {}

    def report(source: str, phase: str, current: int = 0, _total: int | None = None, **_detail: object) -> None:
        if phase == "start":
            started[source] = _time.monotonic()
        elif phase in {"complete", "partial"} and source in started:
            seconds = _time.monotonic() - started[source]
            st.pre_scan_step_timings[f"db refresh {source}"] = seconds
            if not opts.quiet:
                note = ", partial" if phase == "partial" else ""
                st.con.print(f"[dim]  {source}: {seconds:.1f}s ({current:,} records{note})[/dim]", highlight=False)

    return report


def _refresh_vuln_data(opts: ScanOptions, st: ScanState) -> None:
    # ── Fail on an unusable --inventory before paying for anything ───────────
    # A path that does not exist invalidates the whole scan, and detecting it
    # costs one stat(). The refresh below is a multi-minute cold-start download
    # on a machine with no cache, so checking afterwards makes a typo'd path
    # cost minutes before the CLI admits the file was never there. Only
    # existence is decided here; format and parse errors still surface from the
    # loader during discovery, which owns that reporting.
    for _inventory in ((opts.inventory,) if opts.inventory else ()) + opts.extra_inventories:
        if _inventory != "-" and not Path(_inventory).exists():
            raise click.BadParameter(f"Inventory file not found: {_inventory}", param_hint="--inventory")

    # ── Vuln-data freshness snapshot + auto-refresh ──────────────────────────
    # Single source of truth for "where did the vuln data come from, how old is
    # it, is it stale". Computed once here, surfaced to the user below, and
    # attached to the report so the API/MCP can return it. Offline/airgapped
    # callers (``--offline`` or AGENT_BOM_VULN_DB_OFFLINE) never trigger a
    # network refresh — they use whatever cache exists.
    st.vuln_freshness = None
    st.pre_scan_step_timings = {}
    if opts.demo:
        st.vuln_freshness = bundled_demo_freshness()
    else:
        try:
            st.vuln_freshness = compute_freshness(offline=opts.offline)
        except Exception:
            st.vuln_freshness = None  # Never block a scan on a freshness probe failure

    # Auto-refresh stale/missing DB if enabled (skip side-effect-light modes,
    # skip in offline mode). Never fail the scan on a refresh error — fall back
    # to live API or the existing cache.
    if (
        opts.auto_update_db
        and not opts.demo
        and not opts.no_scan
        and not opts.dry_run
        and not opts.offline
        and st.vuln_freshness is not None
    ):
        source_list = [s.strip() for s in opts.db_sources.split(",")] if opts.db_sources else None
        # Explicit --db-source always syncs; otherwise respect the age threshold
        # (idempotent: a fresh cache is not re-synced).
        if source_list or should_refresh(st.vuln_freshness, offline=opts.offline):
            from agent_bom.db.sync import sync_db

            db_path = _db_schema.DB_PATH
            osv_ecosystems = _osv_ecosystems_for_refresh(opts, db_path)
            if not opts.quiet and not opts.no_scan:
                src_msg = f" (sources: {', '.join(source_list)})" if source_list else ""
                scope_msg = " (application ecosystems of OSV)" if osv_ecosystems else ""
                st.con.print(f"[dim]Refreshing local vuln DB{src_msg}{scope_msg} …[/dim]")
            _refresh_t0 = _time.monotonic()
            try:
                sync_db(
                    sources=source_list,
                    osv_ecosystems=osv_ecosystems,
                    nvd_time_budget=_cold_start_nvd_budget(db_path),
                    progress=_source_timing_reporter(opts, st),
                )
                # Recompute so the surfaced freshness reflects the fresh cache.
                st.vuln_freshness = compute_freshness(offline=opts.offline)
            except Exception as _db_exc:
                logger.warning("Auto DB refresh failed: %s", _db_exc)
            finally:
                st.pre_scan_step_timings["db refresh"] = _time.monotonic() - _refresh_t0


def _emit_dry_run(opts: ScanOptions, st: ScanState) -> None:
    # ── Dry-run: show access plan without scanning ────────────────────────────
    if opts.dry_run:
        _agents_patchable("emit_dry_run_plan")(
            st.con,
            inventory=opts.inventory,
            no_discover=opts.no_discover,
            project=opts.project,
            config_dir=opts.config_dir,
            code_paths=opts.code_paths,
            ai_inventory_paths=opts.ai_inventory_paths,
            tf_dirs=opts.tf_dirs,
            agent_projects=opts.agent_projects,
            jupyter_dirs=opts.jupyter_dirs,
            model_dirs=opts.model_dirs,
            dataset_dirs=opts.dataset_dirs,
            scan_pii=opts.scan_pii,
            training_dirs=opts.training_dirs,
            gha_path=opts.gha_path,
            skill_paths=opts.skill_paths,
            no_skill=opts.no_skill,
            skill_only=opts.skill_only,
            images=opts.images,
            aws=opts.aws,
            aws_region=opts.aws_region,
            no_aws_lambda=opts.no_aws_lambda,
            aws_include_eks=opts.aws_include_eks,
            aws_include_step_functions=opts.aws_include_step_functions,
            aws_include_ec2=opts.aws_include_ec2,
            aws_include_iam=opts.aws_include_iam,
            azure_flag=opts.azure_flag,
            gcp_flag=opts.gcp_flag,
            gcp_project=opts.gcp_project,
            databricks_flag=opts.databricks_flag,
            snowflake_flag=opts.snowflake_flag,
            coreweave_flag=opts.coreweave_flag,
            nebius_flag=opts.nebius_flag,
            hf_flag=opts.hf_flag,
            wandb_flag=opts.wandb_flag,
            mlflow_flag=opts.mlflow_flag,
            openai_flag=opts.openai_flag,
            ollama_flag=opts.ollama_flag,
            ollama_host=opts.ollama_host,
            mcp_registry_flag=opts.mcp_registry_flag,
            snyk_flag=opts.snyk_flag,
            enrich=opts.enrich,
        )
        raise StopScan


def _report_vuln_data_freshness(opts: ScanOptions, st: ScanState) -> None:
    # Pre-scan: surface the vuln-data freshness indicator. Replaces the bare
    # "No local vulnerability DB found" warning with an actionable line that
    # states the source(s) + age, and warns prominently when the cache is in a
    # clear-danger state (very stale, or offline with nothing usable cached).
    if not opts.no_scan and st.vuln_freshness is not None and not opts.quiet:
        try:
            _line = st.vuln_freshness.summary_line()
            if st.vuln_freshness.danger:
                st.con.print(f"[red]⚠ {_line}[/red]")
            elif st.vuln_freshness.stale or st.vuln_freshness.mode == "live":
                st.con.print(f"[yellow]⚠ {_line}[/yellow]")
            else:
                st.con.print(f"[dim]{_line}[/dim]")
        except Exception:
            pass  # Never block a scan due to a freshness render failure

    # Day-based DB-freshness signal (non-enforcing by default). Separate from the
    # hour-based auto-refresh above: fires a loud, actionable warning once the
    # local vuln DB crosses AGENT_BOM_DB_STALE_DAYS (default 14). It measures
    # *local data* staleness, so it fires even under --offline. The opt-in gate
    # (--require-fresh-db / AGENT_BOM_REQUIRE_FRESH_DB) turns a stale DB into a
    # policy-gate failure (exit 3); by default the scan only warns and continues.
    if not opts.no_scan and st.vuln_freshness is not None:
        try:
            from agent_bom.vuln_freshness import db_stale_days_threshold, db_staleness, require_fresh_db_env

            _db_stale, _db_age = db_staleness(st.vuln_freshness)
        except Exception:
            _db_stale, _db_age = False, None
        if _db_stale:
            _stale_days = db_stale_days_threshold()
            if not opts.quiet:
                st.con.print(stale_db_warning(_db_age, _stale_days, offline=bool(opts.offline)))
            if opts.require_fresh_db or require_fresh_db_env():
                st.con.print("[red]--require-fresh-db is set and the local vuln DB is stale — failing (exit 3).[/red]")
                sys.exit(3)


def stale_db_warning(age_days: int | None, threshold_days: int, *, offline: bool) -> str:
    """Stale local-DB warning: the age, what it means for this scan, and the exact refresh command."""
    age = f"{age_days} day{'s' if age_days != 1 else ''} old" if age_days is not None else "missing or undated"
    consequence = (
        "--offline uses only local data, so recent CVEs may be missed."
        if offline
        else "This scan also checks OSV live, but local-only matches may be outdated."
    )
    return (
        f"[bold yellow]⚠ Vulnerability DB is stale[/bold yellow] ({age}; threshold {threshold_days} days). "
        f"{consequence} Refresh it: [bold]agent-bom db update[/bold]"
    )


def _run_iac_only(opts: ScanOptions, st: ScanState) -> None:
    # ── IaC-only fast path ───────────────────────────────────────────────────
    # When invoked via `agent-bom iac <paths>` (iac_paths set + no_scan=True),
    # skip ALL discovery, package extraction, and network calls entirely.
    # This prevents MCP config discovery, lockfile scanning, and registry
    # lookups from running when the user only asked for IaC misconfiguration checks.
    if opts._iac_only and (opts.iac_paths or opts.k8s_live):
        run_iac_only_scan(
            con=st.con,
            iac_paths=opts.iac_paths,
            k8s_live=opts.k8s_live,
            k8s_live_namespace=opts.k8s_live_namespace,
            k8s_live_all_namespaces=opts.k8s_live_all_namespaces,
            k8s_live_context=opts.k8s_live_context,
            output=opts.output,
            output_format=opts.output_format,
            no_tree=opts.no_tree,
            quiet=opts.quiet,
            no_color=opts.no_color,
            open_report=opts.open_report,
            compliance_export=opts.compliance_export,
            mermaid_mode=opts.mermaid_mode,
            push_gateway=opts.push_gateway,
            otel_endpoint=opts.otel_endpoint,
            baseline=opts.baseline,
            delta_mode=opts.delta_mode,
            verbose=opts.verbose,
            exclude_unfixable=opts.exclude_unfixable,
            fixable_only=opts.fixable_only,
            fail_on_severity=opts.fail_on_severity,
            ignore_file=opts.ignore_file,
            policy=opts.policy,
        )
        raise StopScan


def run_preflight(opts: ScanOptions, st: ScanState) -> None:
    """Offline mode, vuln-data freshness, and the dry-run / IaC-only exits."""
    _apply_offline_mode(opts, st)
    _refresh_vuln_data(opts, st)
    _emit_dry_run(opts, st)
    _report_vuln_data_freshness(opts, st)
    _run_iac_only(opts, st)
