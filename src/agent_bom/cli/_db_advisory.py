"""``agent-bom db advisory`` — operator-declared advisories matched against saved scans.

Declare an advisory before feeds publish it, then match it against stored scan
history without rescanning. Findings carry ``provenance: operator_advisory``.
Exit codes for ``match``: 0 when matching completed (findings or not), 2 when
the result is incomplete (no saved scan, or a version could not be ordered).
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import ValidationError

from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.db.operator_advisories import (
    load_local_advisories,
    local_affected_answer,
    match_local,
    remove_local_advisory,
    save_local_advisory,
)
from agent_bom.scanners.advisory_affected import MAX_LIMIT, page_answer
from agent_bom.scanners.operator_advisory import OperatorAdvisory


@click.group("advisory", cls=SuggestingGroup)
def advisory_group() -> None:
    """Declare emergency advisories and match them against saved scans."""


@advisory_group.command("add")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Advisory JSON.")
def advisory_add(file_path: Path) -> None:
    """Declare (or replace) an operator advisory from a JSON file."""
    try:
        advisory = OperatorAdvisory.model_validate(json.loads(file_path.read_text()))
    except (ValidationError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"invalid advisory: {exc.__class__.__name__}: {str(exc).splitlines()[0]}") from exc
    save_local_advisory(advisory)
    click.echo(f"Declared operator advisory {advisory.id} ({len(advisory.affected)} affected product(s)).")


@advisory_group.command("list")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table", show_default=True)
def advisory_list(fmt: str) -> None:
    """List declared operator advisories."""

    advisories = load_local_advisories()
    if fmt == "json":
        click.echo(json.dumps({"advisories": [a.model_dump(mode="json") for a in advisories]}, indent=2))
        return
    if not advisories:
        click.echo("No operator advisories declared.")
    for advisory in advisories:
        click.echo(f"{advisory.id}\t{advisory.severity}\t{advisory.summary}")


@advisory_group.command("remove")
@click.argument("advisory_id")
def advisory_remove(advisory_id: str) -> None:
    """Retire an operator advisory."""

    if not remove_local_advisory(advisory_id):
        raise click.ClickException(f"operator advisory {advisory_id} is not declared")
    click.echo(f"Removed operator advisory {advisory_id}.")


@advisory_group.command("match")
@click.option("--id", "advisory_id", default=None, help="Match one advisory (default: all declared).")
@click.option(
    "--report",
    "reports",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Saved JSON report or SBOM to match (repeatable). Default: most recent saved scan.",
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table", show_default=True)
def advisory_match(advisory_id: str | None, reports: tuple[Path, ...], fmt: str) -> None:
    """Match operator advisories against stored scan inventory (no rescan)."""

    advisories = [a for a in load_local_advisories() if advisory_id is None or advisory_id in a.identifiers]
    if not advisories:
        raise click.ClickException("no matching operator advisory is declared")
    result = match_local(advisories, list(reports))
    if fmt == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        _print_table(result.to_dict())
    if not result.complete:
        raise SystemExit(2)


_VERDICT_LABELS = {
    "affected": "affected",
    "possibly_affected": "possibly affected — verify distro advisory",
    "not_affected": "not affected",
}


@advisory_group.command("affected")
@click.argument("advisory_id")
@click.option(
    "--report",
    "reports",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Saved JSON report or SBOM to check (repeatable). Default: most recent saved scan.",
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table", show_default=True)
def advisory_affected(advisory_id: str, reports: tuple[Path, ...], fmt: str) -> None:
    """Which scanned assets an advisory (declared, or a local feed record) affects."""

    answer = local_affected_answer(advisory_id, list(reports))
    if answer is None:
        raise click.ClickException(f"{advisory_id} is neither declared locally nor in the local vulnerability DB")
    body = page_answer(answer, tenant_id="local", limit=MAX_LIMIT)
    body["rows"] = answer["rows"]
    body["count"], body["has_more"], body["next_cursor"] = len(answer["rows"]), False, None
    if fmt == "json":
        click.echo(json.dumps(body, indent=2))
    else:
        _print_affected(body)
    if not body["complete"]:
        raise SystemExit(2)


def _print_affected(body: dict) -> None:
    for row in body["rows"]:
        patch = row["fixed_version"] or ("verify distro advisory" if row["verdict"] == "possibly_affected" else "-")
        package = f"{row['package'].get('name', '')}@{row['installed_version']}"
        click.echo(f"{_VERDICT_LABELS[row['verdict']]}\t{row['asset_label']}\t{package}\tpatch to {patch}")
    summary = body["summary"]
    click.echo(
        f"{summary['affected']} affected, {summary['possibly_affected']} possibly affected, {summary['not_affected']} not affected; "
        f"{summary['clean_scanned']} of {summary['assets_examined']} scanned asset(s) not found affected in what was scanned"
    )
    if not body["complete"]:
        reason = "no saved scan found" if not summary["reports_examined"] else "some versions could not be ordered"
        click.echo(f"INCOMPLETE: {reason}; this is not a clean result.", err=True)


def _print_table(body: dict) -> None:
    for finding in body["findings"]:
        pkg = finding["package"]
        fixed = finding["fixed_version"] or "no fix declared"
        click.echo(f"{finding['advisory_id']}\t{pkg['name']}@{pkg['version']}\tfixed in {fixed}\t{finding['asset']['server']}")
    for row in body["superseded"]:
        click.echo(f"{row['advisory_id']}\t{row['package']}\tsuperseded by feed record {row['feed_id']}")
    for row in body["indeterminate"]:
        click.echo(f"{row['advisory_id']}\t{row['package']}\tindeterminate: {row.get('detail') or row['reason'].replace('_', ' ')}")
    click.echo(
        f"{len(body['findings'])} operator-advisory finding(s) across {body['packages_examined']} package(s) "
        f"in {body['reports_examined']} saved scan(s)"
    )
    if not body["complete"]:
        reason = "no saved scan found" if not body["reports_examined"] else f"{len(body['indeterminate'])} package(s) indeterminate"
        click.echo(f"INCOMPLETE: {reason}; this is not a clean result.", err=True)
