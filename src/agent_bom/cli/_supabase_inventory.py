"""Explicit, read-only Supabase inventory and native-advisor command."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import click

from agent_bom.cli._cloud_inventory_io import (
    CollectionScopeMismatchError,
    ConnectorPushError,
    _write_report,
    persist_graph,
    push_report,
    read_token,
)
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
@click.option("--project-ref", "project_refs", multiple=True, help="Explicit project ref; repeat for each approved project.")
@click.option("--organization-slug", default=None, help="Read an explicit organization, all its projects and configured memberships.")
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
@click.option(
    "--push-url",
    default=None,
    metavar="URL",
    help="Push each project's inventory to a control plane (base URL or /v1/results/push); it joins the current estate graph.",
)
@click.option("--push-api-key", default=None, envvar="AGENT_BOM_PUSH_API_KEY", metavar="KEY", help="API key for push authentication.")
def supabase_cmd(
    project_refs: tuple[str, ...],
    organization_slug: str | None,
    token_file: Path,
    output: Path,
    graph_db: Path | None,
    tenant: str | None,
    push_url: str | None,
    push_api_key: str | None,
) -> None:
    """Read scoped Supabase project metadata and native security advisors.

    Never resumes projects, queries data, executes advisors or reads API keys.
    Exit 2 retains a partial report but leaves the previous graph snapshot intact.
    Use a dedicated graph database for this scoped inventory, not a fleet scan DB.
    A push sends one target per project; a partial project keeps its earlier evidence.
    """
    from agent_bom.cloud.supabase_inventory import collect_report

    try:
        token = read_token(token_file, output, graph_db)
        tenant_id = resolve_cli_tenant_id_strict(tenant)
        if bool(project_refs) == bool(organization_slug):
            raise ValueError("Choose explicit project refs or one organization")
        report = collect_report(project_refs=list(project_refs), token=token, organization=organization_slug)
        report["scan_id"] = str(uuid4())
        report["persistence"] = {"graph": "not_requested"}
        # Persist the receipt first, including failures. Failed collection must
        # not publish a replacement snapshot that can hide previously seen assets.
        if graph_db is not None:
            report["persistence"]["graph"] = "skipped_incomplete" if report["status"] != "ok" else "pending"
        _write_report(output, report)
        if graph_db is not None and report["status"] == "ok":
            _persist_report(report, graph_db, tenant_id, output)
        if push_url:
            push_report(report, push_url, push_api_key, output)
    except CollectionScopeMismatchError as exc:
        raise click.ClickException("Collection scope changed; use a separate graph database") from exc
    except ConnectorPushError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(sanitize_error(exc, generic=True)) from exc
    project_count = sum(len(i["projects"]) for i in report["cloud_inventory"])
    click.echo(f"Supabase: {report['status']}; {project_count} projects; {len(report['findings'])} native findings.")
    click.echo(f"Report: {output}. Empty advisors do not establish clean posture.")
    if report["status"] != "ok":
        raise click.exceptions.Exit(2)
