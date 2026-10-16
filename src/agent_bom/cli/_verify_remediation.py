"""Local, bounded installed-package remediation receipts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from agent_bom.cli._remediate import remediate_cmd


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(8_000_001)
    if len(raw) > 8_000_000:
        raise ValueError("receipt exceeds input budget")
    value = json.loads(raw, object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise ValueError("a JSON object is required")
    return value


def _save(path: Path, value: dict[str, Any]) -> None:
    # Validate serialization before creating an artifact; never overwrite evidence.
    encoded = json.dumps(value, indent=2, allow_nan=False) + "\n"
    with path.open("x", encoding="utf-8") as stream:
        stream.write(encoded)


@click.group("verify-remediation")
def verify_remediation() -> None:
    """Capture and compare installed Python metadata against one pinned advisory.

    Read-only for the installation. Receipts do not prove running-process state
    or authenticate their producer. No campaign is automatically closed.
    """


@verify_remediation.command("capture")
@click.option("--site-packages", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--package", required=True, help="Exact PyPI distribution name.")
@click.option("--tenant-id", required=True, help="Local evidence label; does not grant server access.")
@click.option("--advisory", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="Retained OSV JSON advisory.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.pass_context
def capture(ctx: click.Context, site_packages: Path, package: str, tenant_id: str, advisory: Path, output: Path) -> None:
    """Retain one fresh observation without importing the inspected package."""
    from agent_bom.evidence.package_remediation import capture_package

    try:
        if output.exists():
            raise ValueError("output exists")
        result = capture_package(site_packages, package=package, tenant_id=tenant_id, advisory=_read(advisory))
        _save(output, result)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise click.ClickException("Capture failed: check input scope, JSON and file permissions; choose a new output path.") from exc
    click.echo(json.dumps({"artifact": str(output), "digest": result["digest"], "collection_status": result["collection_status"]}))
    ctx.exit(0 if result["collection_status"] == "complete" else 2)


@verify_remediation.command("compare")
@click.option("--before", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--after", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--max-age-seconds", type=click.IntRange(1, 86400), default=3600, show_default=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.pass_context
def compare(ctx: click.Context, before: Path, after: Path, max_age_seconds: int, output: Path) -> None:
    """Save a comparison: exit 0 verified, 1 still affected, 2 unavailable."""
    from agent_bom.evidence.package_remediation import compare_packages

    try:
        result = compare_packages(_read(before), _read(after), max_age_seconds=max_age_seconds)
        _save(output, result)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise click.ClickException("Comparison failed: check receipt JSON and file permissions; choose a new output path.") from exc
    click.echo(json.dumps({"artifact": str(output), "outcome": result["outcome"], "reason_codes": result["reason_codes"]}))
    ctx.exit({"verified_for_selected_advisory": 0, "still_affected": 1, "unavailable_evidence": 2}[result["outcome"]])


def register_remediation_commands(group: click.Group) -> None:
    group.add_command(remediate_cmd, "remediate")
    group.add_command(verify_remediation, "verify-remediation")
