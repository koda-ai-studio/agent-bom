"""``agent-bom db prune`` — remove stale current-estate projection caches from the local state directory."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import click

from agent_bom import config
from agent_bom.storage import projection_cache

ANALYTICS_MIRROR_HINT = (
    "The local analytics mirror is bounded separately: inspect it with `agent-bom report storage` "
    "and compact it with `agent-bom report prune --apply --compact`."
)


@click.command("prune")
@click.option("--yes", "confirmed", is_flag=True, help="Delete the listed files. Without it the command only previews.")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
def db_prune_cmd(confirmed: bool, output_format: str) -> None:
    """Preview or remove stale current-estate projection caches (dry run by default)."""
    from agent_bom.db.graph_store import default_graph_db_path

    directory = projection_cache.cache_directory()
    active = projection_cache.cache_path_for(projection_cache.configured_locator(default_graph_db_path()))
    now = time.time()
    candidates = _describe(
        projection_cache.sweep_projection_cache(
            directory,
            active=active,
            keep_latest=config.CURRENT_ESTATE_CACHE_KEEP_LATEST,
            max_age_days=config.CURRENT_ESTATE_CACHE_MAX_AGE_DAYS,
            now=now,
            dry_run=True,
        ),
        now,
    )
    removed: list[Path] = []
    if confirmed and candidates:
        removed = projection_cache.sweep_projection_cache(
            directory,
            active=active,
            keep_latest=config.CURRENT_ESTATE_CACHE_KEEP_LATEST,
            max_age_days=config.CURRENT_ESTATE_CACHE_MAX_AGE_DAYS,
            now=now,
        )
        candidates = [entry for entry in candidates if Path(entry["path"]) in set(removed)]
    payload = {
        "directory": str(directory),
        "active": str(active),
        "dry_run": not confirmed,
        "keep_latest": config.CURRENT_ESTATE_CACHE_KEEP_LATEST,
        "max_age_days": config.CURRENT_ESTATE_CACHE_MAX_AGE_DAYS,
        "count": len(candidates),
        "total_bytes": sum(entry["bytes"] for entry in candidates),
        "candidates": candidates,
        "analytics_mirror": ANALYTICS_MIRROR_HINT,
    }
    if output_format == "json":
        click.echo(json.dumps(payload, indent=2))
        return
    _echo_table(payload)


def _describe(paths: list[Path], now: float) -> list[dict[str, Any]]:
    entries = []
    for path in paths:
        try:
            age_days = round((now - projection_cache.last_used(path)) / 86_400, 1)
        except OSError:
            age_days = None
        entries.append({"path": str(path), "bytes": projection_cache.cache_bytes(path), "age_days": age_days})
    return entries


def _echo_table(payload: dict[str, Any]) -> None:
    verb = "Removed" if not payload["dry_run"] else "Would remove"
    click.echo(f"Projection cache: {payload['directory']}")
    click.echo(f"Keeping the newest {payload['keep_latest']} and the active projection {Path(payload['active']).name}")
    if payload["max_age_days"] > 0:
        click.echo(f"Age cap: {payload['max_age_days']} day(s) since last use (AGENT_BOM_CURRENT_ESTATE_CACHE_MAX_AGE_DAYS)")
    for entry in payload["candidates"]:
        age = "unknown" if entry["age_days"] is None else f"{entry['age_days']}d"
        click.echo(f"  {verb}: {Path(entry['path']).name}  {entry['bytes']} bytes  age {age}")
    click.echo(f"{verb} {payload['count']} file(s), {payload['total_bytes']} bytes")
    if payload["dry_run"] and payload["count"]:
        click.echo("Dry run; re-run with --yes to delete them.")
    click.echo(ANALYTICS_MIRROR_HINT)
