"""CLI commands for the local vulnerability database.

Commands:
    agent-bom db update   — sync from OSV / Alpine secdb / EPSS / KEV / GHSA / NVD
    agent-bom db update-frameworks — refresh local MITRE framework catalogs
    agent-bom db status   — show DB stats and last-sync timestamps
    agent-bom db path     — print the DB file path
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import click

from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.db.sync import GHSA_ECOSYSTEMS, OSV_APPLICATION_ECOSYSTEMS

if TYPE_CHECKING:
    from rich.console import Console


@click.group("db", cls=SuggestingGroup)
def db_cmd() -> None:
    """Manage the local vulnerability database."""


@db_cmd.command("update")
@click.option(
    "--source",
    "sources",
    multiple=True,
    type=click.Choice(["osv", "alpine", "debian", "epss", "kev", "ghsa", "nvd"], case_sensitive=False),
    help="Which sources to sync (default: osv, alpine, debian, epss, kev, nvd). Repeatable. "
    "Use --source alpine to sync Alpine package secfix data from Alpine secdb. "
    "Use --source debian to sync the Debian Security Tracker (authoritative per-release "
    "status + backported fixes, including end-of-life releases such as buster/Debian 10). "
    "Use --source ghsa to sync GitHub Security Advisories (all ecosystems). "
    "Use --source nvd to ingest CVEs NVD published or modified recently, with their CPE ranges "
    "(14-day window without NVD_API_KEY, 120 days with it), and backfill unknown severities.",
)
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
@click.option(
    "--max-osv-entries",
    type=int,
    default=0,
    help="Limit OSV entries (for testing). 0 = unlimited.",
    hidden=True,
)
@click.option(
    "--max-ghsa-entries",
    type=int,
    default=5000,
    help="Limit GHSA advisories to ingest (default: 5000).",
    hidden=True,
)
@click.option(
    "--max-nvd-entries",
    type=int,
    default=None,
    help="Cap NVD records read per run (default: whole window with NVD_API_KEY, 60,000 without) and keyless CVSS lookups (default 50).",
    hidden=True,
)
@click.option(
    "--nvd-time-budget",
    type=click.FloatRange(min=0),
    default=None,
    help="Seconds the NVD sync may run before stopping as PARTIAL and resuming next time "
    "(default: 480 without NVD_API_KEY, unlimited with it; env AGENT_BOM_NVD_TIME_BUDGET_SECONDS; 0 = no limit).",
)
@click.option(
    "--osv-ecosystem",
    "osv_ecosystems",
    multiple=True,
    type=click.Choice(OSV_APPLICATION_ECOSYSTEMS, case_sensitive=False),
    help="Sync only selected OSV application ecosystems instead of the all-ecosystems archive. Repeatable.",
)
@click.option(
    "--ghsa-ecosystems",
    "ghsa_ecosystems",
    multiple=True,
    type=click.Choice(GHSA_ECOSYSTEMS, case_sensitive=False),
    help="Filter GHSA sync to specific ecosystems (default: all). Repeatable.",
)
def db_update(
    sources: tuple,
    db_path: str | None,
    max_osv_entries: int,
    max_ghsa_entries: int,
    max_nvd_entries: int | None,
    nvd_time_budget: float | None,
    osv_ecosystems: tuple,
    ghsa_ecosystems: tuple,
) -> None:
    """Download and sync the local vulnerability database.

    Pulls from OSV.dev (bulk export), Alpine secdb, the Debian Security Tracker,
    FIRST EPSS scores, and CISA KEV catalog by default. The Debian Security Tracker
    provides authoritative per-release status and backported fix versions, including
    end-of-life releases (e.g. buster/Debian 10) that OSV no longer carries.
    Pass --source ghsa to also fetch GitHub Security Advisories across all supported
    ecosystems (pip, npm, go, maven, nuget, rubygems, cargo, composer, swift,
    pub, erlang, actions).
    Pass --source nvd to ingest recently published/modified NVD CVEs with their CPE
    ranges (14-day window keyless, 120 days with NVD_API_KEY); partial windows resume.

    Requires internet access. Use --osv-ecosystem for a smaller, explicitly
    scoped application-ecosystem archive. The OSV all-ecosystems archive can
    exceed 1 GB; exact download progress is shown when the server reports its
    size. Repeat syncs download the selected archive again, then update records
    by advisory ID.
    """
    from rich.console import Console
    from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    from agent_bom.cli._db_progress import SyncProgress, progress_note
    from agent_bom.core.settings import env_opt
    from agent_bom.db.sync import DEFAULT_SYNC_SOURCES, sync_db

    con = Console()
    if sources and osv_ecosystems and "osv" not in {str(source).lower() for source in sources}:
        raise click.UsageError("--osv-ecosystem requires --source osv when --source is specified")
    selected = list(sources) or (["osv"] if osv_ecosystems else list(DEFAULT_SYNC_SOURCES))
    con.print(f"[bold]Syncing local vuln DB[/bold] — sources: {', '.join(selected)}")
    selected_sources = {str(source).lower() for source in selected}
    if "osv" in selected_sources and osv_ecosystems:
        con.print(
            "Coverage is limited to the selected OSV ecosystem(s): "
            f"{', '.join(osv_ecosystems)}. Other ecosystems remain uncovered for offline scans."
        )
    for note in progress_note(selected_sources, osv_ecosystems, nvd_keyless=not env_opt("NVD_API_KEY")):
        con.print(note)

    renderer = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TimeElapsedColumn(),
        console=con,
        transient=False,
    )
    _progress = SyncProgress(con, renderer)

    try:
        with renderer:
            results = sync_db(
                path=Path(db_path) if db_path else None,
                sources=selected,
                max_osv_entries=max_osv_entries,
                max_ghsa_entries=max_ghsa_entries,
                max_nvd_entries=max_nvd_entries,
                nvd_time_budget=nvd_time_budget,
                osv_ecosystems=list(osv_ecosystems) if osv_ecosystems else None,
                ghsa_ecosystems=list(ghsa_ecosystems) if ghsa_ecosystems else None,
                progress=_progress,
            )
    except Exception as exc:
        con.print(f"[red]Sync failed: {exc}[/red]")
        raise SystemExit(1) from exc

    _print_sync_results(con, Path(db_path) if db_path else None, results)
    con.print("[bold green]Done.[/bold green]")


from agent_bom.cli._db_progress import DONE_MARKS as _DONE_MARKS  # noqa: E402


def _print_sync_results(con: Console, db_path: Path | None, results: dict) -> None:
    """Per-source record counts; a rate-limited, timed-out or capped NVD window is PARTIAL, never complete."""
    from agent_bom.db.schema import DB_PATH, init_db
    from agent_bom.db.sync_common import _read_sync_metadata

    meta: dict = {}
    if "nvd" in results:
        conn = init_db(db_path or DB_PATH)
        try:
            meta = _read_sync_metadata(conn, "nvd")
        finally:
            conn.close()
    partial = meta.get("status") == "partial"
    for src, count in results.items():
        con.print(f"  {_DONE_MARKS['partial' if src == 'nvd' and partial else 'complete']} {src}: {count:,} records")
    if not partial:
        return
    if meta.get("partial_reason") == "time_budget":
        con.print(
            f"  [yellow]![/yellow] nvd: PARTIAL (time_budget) — stopped at the {meta.get('time_budget_seconds') or 0:g}-second "
            "time budget with the window checkpoint saved; run `agent-bom db update --source nvd` again to resume, "
            "or raise --nvd-time-budget / AGENT_BOM_NVD_TIME_BUDGET_SECONDS (0 = no limit)."
        )
        return
    con.print(
        f"  [yellow]![/yellow] nvd: PARTIAL ({meta.get('partial_reason')}) — this is not a complete NVD window; "
        "the next `agent-bom db update --source nvd` resumes from the last synced checkpoint."
    )


@db_cmd.command("status")
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
def db_status(db_path: str | None) -> None:
    """Show local vulnerability database statistics and sync timestamps."""
    from pathlib import Path

    from rich.console import Console
    from rich.table import Table

    from agent_bom.db.schema import DB_PATH, db_stats, init_db

    con = Console()
    db_file = Path(db_path) if db_path else DB_PATH

    if not db_file.exists():
        con.print(f"[yellow]No local DB found at {db_file}[/yellow]")
        con.print("Run [bold]agent-bom db update[/bold] to create it.")
        return

    conn = init_db(db_file)
    try:
        stats = db_stats(conn)
        from agent_bom.coverage import covered_os_distros

        os_distros = covered_os_distros(conn)
    finally:
        conn.close()

    con.print(f"[bold]Local vulnerability DB[/bold]  {db_file}")
    con.print(f"  Vulnerabilities : {stats['vuln_count']:,}")
    con.print(f"  Affected ranges : {stats['affected_count']:,}")
    con.print(f"  EPSS scores     : {stats['epss_count']:,}")
    con.print(f"  KEV entries     : {stats['kev_count']:,}")
    if os_distros:
        con.print(f"  OS distros      : {', '.join(os_distros)}")

    meta = stats.get("sync_meta", {})
    if meta:
        from agent_bom.db.schema import db_freshness_days

        age = db_freshness_days(db_file)
        if age is None:
            freshness_msg = "[yellow]Never synced — run agent-bom db update[/yellow]"
        elif age < 1:
            freshness_msg = f"[green]Fresh ({age}d ago)[/green]"
        elif age <= 7:
            freshness_msg = f"[yellow]Aging ({age}d ago) — run agent-bom db update for daily security freshness[/yellow]"
        else:
            freshness_msg = f"[red]Stale ({age}d ago) — run agent-bom db update[/red]"
        con.print(f"  Freshness       : {freshness_msg}")

        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Source")
        table.add_column("Last synced")
        table.add_column("Records", justify="right")
        table.add_column("Coverage")
        for src, info in sorted(meta.items()):
            metadata = info.get("metadata") or {}
            coverage = str(metadata.get("coverage") or metadata.get("mode") or "—")
            if metadata.get("cap_hit"):
                coverage = f"{coverage} [yellow](cap hit)[/yellow]"
            if metadata.get("status") == "partial":
                coverage = f"{coverage} [yellow]partial ({metadata.get('partial_reason')})[/yellow]"
            table.add_row(src, info.get("last_synced") or "—", f"{info.get('count', 0):,}", coverage)
        con.print(table)
    else:
        con.print("  [yellow]No sync data — run agent-bom db update to populate.[/yellow]")

    from agent_bom.mitre_fetch import get_catalog_metadata

    framework_meta = get_catalog_metadata()
    con.print("\n[bold]Framework catalogs[/bold]")
    con.print(
        "  MITRE ATT&CK/CAPEC : "
        f"{framework_meta.get('attack_version') or 'unknown'}"
        f"  [dim]({framework_meta.get('source', 'unknown')}, "
        f"{framework_meta.get('technique_count', 0)} techniques, "
        f"{framework_meta.get('cwe_mapping_count', 0)} CWE mappings)[/dim]"
    )
    updated_at = framework_meta.get("updated_at") or "unknown"
    con.print(f"  Updated at         : {updated_at}")


@db_cmd.command("update-frameworks")
@click.option(
    "--framework",
    "frameworks",
    multiple=True,
    type=click.Choice(["mitre", "atlas"], case_sensitive=False),
    help="Framework catalog to refresh (default: mitre + atlas). Repeatable.",
)
@click.option(
    "--catalog-path",
    type=click.Path(),
    default=None,
    help="Override the local MITRE ATT&CK catalog path (default: ~/.agent-bom/catalogs/mitre_attack_catalog.json).",
)
@click.option(
    "--atlas-catalog-path",
    type=click.Path(),
    default=None,
    help="Override the local MITRE ATLAS catalog path (default: ~/.agent-bom/catalogs/mitre_atlas_catalog.json).",
)
def db_update_frameworks(frameworks: tuple[str, ...], catalog_path: str | None, atlas_catalog_path: str | None) -> None:
    """Refresh locally cached framework catalogs without touching the scan hot path."""
    from pathlib import Path

    from rich.console import Console

    from agent_bom.atlas_fetch import get_catalog_metadata as get_atlas_metadata
    from agent_bom.atlas_fetch import sync_catalog as sync_atlas_catalog
    from agent_bom.mitre_fetch import get_catalog_metadata, sync_catalog

    con = Console()
    selected = [s.lower() for s in frameworks] or ["mitre", "atlas"]

    if "mitre" in selected:
        con.print("[bold]Refreshing framework catalogs[/bold] — mitre")
        catalog = sync_catalog(output_path=Path(catalog_path) if catalog_path else None)
        meta = (
            get_catalog_metadata()
            if catalog_path is None
            else {
                "path": str(Path(catalog_path)),
                "source": catalog.get("source", "synced"),
                "attack_version": catalog.get("attack_version", "unknown"),
                "updated_at": catalog.get("updated_at", ""),
                "technique_count": len(catalog.get("techniques", {})),
                "cwe_mapping_count": len(catalog.get("cwe_to_attack", {})),
                "normalized_sha256": catalog.get("normalized_sha256", ""),
            }
        )
        con.print(
            f"  [green]✓[/green] MITRE ATT&CK/CAPEC: {meta.get('attack_version', 'unknown')} "
            f"[dim]({meta.get('technique_count', 0)} techniques, {meta.get('cwe_mapping_count', 0)} CWE mappings)[/dim]"
        )
        con.print(f"  [dim]Source:[/dim] {meta.get('source', 'unknown')}")
        con.print(f"  [dim]Updated:[/dim] {meta.get('updated_at', '')}")
        con.print(f"  [dim]SHA256:[/dim] {meta.get('normalized_sha256', '')}")
        if meta.get("path"):
            con.print(f"  [dim]Path:[/dim] {meta['path']}")

    if "atlas" in selected:
        con.print("[bold]Refreshing framework catalogs[/bold] — atlas")
        atlas_catalog = sync_atlas_catalog(output_path=Path(atlas_catalog_path) if atlas_catalog_path else None)
        atlas_meta = (
            get_atlas_metadata()
            if atlas_catalog_path is None
            else {
                "path": str(Path(atlas_catalog_path)),
                "source": atlas_catalog.get("source", "synced"),
                "atlas_version": atlas_catalog.get("atlas_version", "unknown"),
                "updated_at": atlas_catalog.get("updated_at", ""),
                "technique_count": len(atlas_catalog.get("techniques", {})),
                "tactic_count": len(atlas_catalog.get("tactics", {})),
                "normalized_sha256": atlas_catalog.get("normalized_sha256", ""),
            }
        )
        con.print(
            f"  [green]✓[/green] MITRE ATLAS: {atlas_meta.get('atlas_version', 'unknown')} "
            f"[dim]({atlas_meta.get('technique_count', 0)} techniques, {atlas_meta.get('tactic_count', 0)} tactics)[/dim]"
        )
        con.print(f"  [dim]Source:[/dim] {atlas_meta.get('source', 'unknown')}")
        con.print(f"  [dim]Updated:[/dim] {atlas_meta.get('updated_at', '')}")
        con.print(f"  [dim]SHA256:[/dim] {atlas_meta.get('normalized_sha256', '')}")
        if atlas_meta.get("path"):
            con.print(f"  [dim]Path:[/dim] {atlas_meta['path']}")

    con.print("[bold green]Done.[/bold green]")


@db_cmd.command("framework-status")
@click.option(
    "--framework",
    "frameworks",
    multiple=True,
    type=click.Choice(["mitre", "atlas"], case_sensitive=False),
    help="Framework catalog to inspect (default: all). Repeatable.",
)
@click.option(
    "--stale-after-days",
    type=int,
    default=180,
    show_default=True,
    help="Mark a bundled framework catalog stale after this many days since upstream snapshot.",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--fail-on-stale",
    is_flag=True,
    help="Exit 1 when any inspected framework catalog is stale, missing, or has zero techniques.",
)
def db_framework_status(frameworks: tuple[str, ...], stale_after_days: int, fmt: str, fail_on_stale: bool) -> None:
    """Show bundled framework catalog freshness (mirrors ``registry status`` shape).

    Used in CI release gates to fail-fast when bundled MITRE catalogs are
    stale or empty.
    """
    import json
    from datetime import datetime, timezone

    from rich.console import Console
    from rich.table import Table

    from agent_bom.atlas import curated_total
    from agent_bom.atlas_fetch import get_catalog_metadata as get_atlas_metadata
    from agent_bom.mitre_fetch import get_catalog_metadata as get_mitre_metadata

    selected = [s.lower() for s in frameworks] or ["mitre", "atlas"]

    def _age_days(updated_at: str) -> int | None:
        if not updated_at:
            return None
        for fmt_ in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(updated_at, fmt_)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return max(0, (datetime.now(timezone.utc) - dt).days)
            except ValueError:
                continue
        return None

    rows: list[dict] = []
    any_stale = False
    if "mitre" in selected:
        meta = get_mitre_metadata()
        age = _age_days(meta.get("updated_at", ""))
        techniques = int(meta.get("technique_count", 0) or 0)
        is_stale = techniques == 0 or (age is not None and age > stale_after_days)
        any_stale = any_stale or is_stale
        rows.append(
            {
                "framework": "mitre_attack",
                "version": meta.get("attack_version", "unknown"),
                "source": meta.get("source", "unknown"),
                "techniques": techniques,
                "updated_at": meta.get("updated_at", ""),
                "age_days": age,
                "stale_after_days": stale_after_days,
                "status": "stale" if is_stale else "fresh",
            }
        )
    if "atlas" in selected:
        meta = get_atlas_metadata()
        age = _age_days(meta.get("updated_at", ""))
        techniques = int(meta.get("technique_count", 0) or 0)
        is_stale = techniques == 0 or (age is not None and age > stale_after_days)
        any_stale = any_stale or is_stale
        rows.append(
            {
                "framework": "mitre_atlas",
                "version": meta.get("atlas_version", "unknown"),
                "source": meta.get("source", "unknown"),
                "techniques": techniques,
                "curated_techniques": curated_total(),
                "updated_at": meta.get("updated_at", ""),
                "age_days": age,
                "stale_after_days": stale_after_days,
                "status": "stale" if is_stale else "fresh",
            }
        )

    if fmt == "json":
        click.echo(json.dumps({"frameworks": rows}, indent=2))
        if fail_on_stale and any_stale:
            raise click.exceptions.Exit(1)
        return

    con = Console()
    table = Table(title="Bundled framework catalog freshness")
    table.add_column("Framework")
    table.add_column("Version")
    table.add_column("Source")
    table.add_column("Techniques", justify="right")
    table.add_column("Updated at")
    table.add_column("Age")
    table.add_column("Status")
    for r in rows:
        status_color = "green" if r["status"] == "fresh" else "red"
        techs = str(r["techniques"])
        if "curated_techniques" in r:
            techs = f"{r['curated_techniques']} curated / {r['techniques']} upstream"
        age_str = "unknown" if r["age_days"] is None else f"{r['age_days']}d"
        table.add_row(
            r["framework"],
            r["version"],
            r["source"],
            techs,
            r["updated_at"] or "—",
            age_str,
            f"[{status_color}]{r['status']}[/{status_color}]",
        )
    con.print(table)
    if fail_on_stale and any_stale:
        raise click.exceptions.Exit(1)


@db_cmd.command("freshness")
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
@click.option(
    "--offline",
    is_flag=True,
    help="Report freshness without considering a live API fallback (airgapped view).",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
def db_freshness_cmd(db_path: str | None, offline: bool, fmt: str) -> None:
    """Show the structured vuln-data freshness indicator (sources, age, staleness).

    This is the same snapshot surfaced on every scan and returned by the API and
    MCP tool, so CI and operators can verify the vuln data is up to date.
    """
    import json
    from pathlib import Path

    from agent_bom.vuln_freshness import compute_freshness

    snapshot = compute_freshness(db_path=Path(db_path) if db_path else None, offline=offline)

    if fmt == "json":
        click.echo(json.dumps(snapshot.to_dict(), indent=2))
        return

    from rich.console import Console

    con = Console()
    line = snapshot.summary_line()
    if snapshot.danger:
        con.print(f"[red]⚠ {line}[/red]")
    elif snapshot.stale or snapshot.mode == "live":
        con.print(f"[yellow]⚠ {line}[/yellow]")
    else:
        con.print(f"[green]✓ {line}[/green]")


@db_cmd.command("path")
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
def db_path_cmd(db_path: str | None) -> None:
    """Print the local vulnerability database file path."""
    from pathlib import Path

    from agent_bom.db.schema import DB_PATH

    click.echo(str(Path(db_path) if db_path else DB_PATH))


from agent_bom.cli._db_advisory import advisory_group  # noqa: E402
from agent_bom.cli._db_prune import db_prune_cmd  # noqa: E402

db_cmd.add_command(advisory_group)
db_cmd.add_command(db_prune_cmd)
