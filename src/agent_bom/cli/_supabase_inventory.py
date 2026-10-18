"""Explicit, read-only Supabase inventory and native-advisor command."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import click

from agent_bom.cli._cloud_inventory_io import CollectionScopeMismatchError, _write_report, persist_graph, read_token
from agent_bom.cli._tenant import resolve_cli_tenant_id_strict
from agent_bom.security import sanitize_error


def _persist_report(report: dict, graph_db: Path, tenant_id: str, output: Path) -> None:
    """Retain exact project scope and native-finding correlation receipts."""
    for receipt in report["coverage"]:
        receipt["correlated"] = receipt["capability"] == "security_advisors" and any(
            finding["evidence"]["project_ref"] == receipt["project_ref"] for finding in report["findings"]
        )
    expected = {project["node_id"] for inventory in report["cloud_inventory"] for project in inventory["projects"]}
    persist_graph(report, graph_db, tenant_id, output, scope_entity_types={"cloud_resource"}, scope_node_ids=expected)


@click.command("supabase")
@click.option("--project-ref", "project_refs", multiple=True, required=True, help="Explicit project ref; repeat for each approved project.")
@click.option(
    "--token-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Private JSON file containing a token field. Requires project_admin_read and advisors_read.",
)
@click.option(
    "--output", type=click.Path(dir_okay=False, path_type=Path), required=True, help="Normalized JSON report and capability receipts."
)
@click.option("--graph-db", type=click.Path(dir_okay=False, path_type=Path), help="Optional dedicated SQLite graph snapshot database.")
@click.option("--tenant", default=None, help="Tenant for graph persistence; uses the standard CLI tenant resolution.")
def supabase_cmd(project_refs: tuple[str, ...], token_file: Path, output: Path, graph_db: Path | None, tenant: str | None) -> None:
    """Read scoped Supabase project metadata and native security advisors.

    Never resumes projects, queries data, executes advisors or reads API keys.
    Exit 2 retains a partial report but leaves the previous graph snapshot intact.
    Use a dedicated graph database for this scoped inventory, not a fleet scan DB.
    """
    from agent_bom.cloud.supabase_inventory import collect_report

    try:
        token = read_token(token_file, output, graph_db)
        tenant_id = resolve_cli_tenant_id_strict(tenant)
        report = collect_report(project_refs=list(project_refs), token=token)
        report["scan_id"] = str(uuid4())
        report["persistence"] = {"graph": "not_requested"}
        # Persist the receipt first, including failures. Failed collection must
        # not publish a replacement snapshot that can hide previously seen assets.
        if graph_db is not None:
            report["persistence"]["graph"] = "skipped_incomplete" if report["status"] != "ok" else "pending"
        _write_report(output, report)
        if graph_db is not None and report["status"] == "ok":
            _persist_report(report, graph_db, tenant_id, output)
    except CollectionScopeMismatchError as exc:
        raise click.ClickException("Collection scope changed; use a separate graph database") from exc
    except Exception as exc:
        raise click.ClickException(sanitize_error(exc, generic=True)) from exc
    click.echo(f"Supabase: {report['status']}; {len(report['cloud_inventory'])} projects; {len(report['findings'])} native findings.")
    click.echo(f"Report: {output}. Empty advisors do not establish clean posture.")
    if report["status"] != "ok":
        raise click.exceptions.Exit(2)
