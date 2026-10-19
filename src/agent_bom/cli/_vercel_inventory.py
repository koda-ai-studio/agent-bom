"""Explicit-team Vercel inventory and configuration evidence command."""

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


@click.command("vercel")
@click.option("--team-id", required=True, help="Explicit approved Vercel team ID.")
@click.option(
    "--token-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Private JSON file with a token field.",
)
@click.option(
    "--output", type=click.Path(dir_okay=False, path_type=Path), required=True, help="Normalized inventory and configuration evidence JSON."
)
@click.option("--graph-db", type=click.Path(dir_okay=False, path_type=Path), help="Dedicated SQLite graph database for this team.")
@click.option("--tenant", default=None, help="Tenant for graph persistence.")
@click.option(
    "--push-url",
    default=None,
    metavar="URL",
    help="Push this team's inventory to a control plane (base URL or /v1/results/push); it joins the current estate graph.",
)
@click.option("--push-api-key", default=None, envvar="AGENT_BOM_PUSH_API_KEY", metavar="KEY", help="API key for push authentication.")
def vercel_cmd(
    team_id: str,
    token_file: Path,
    output: Path,
    graph_db: Path | None,
    tenant: str | None,
    push_url: str | None,
    push_api_key: str | None,
) -> None:
    """Read team projects and the last 24 hours of deployments.

    No environment values, source contents, deployment writes or runtime scans.
    Exit 2 preserves partial evidence without replacing a prior graph snapshot;
    a partial push is recorded as partial and keeps the team's earlier evidence.
    """
    from agent_bom.cloud.vercel_inventory import collect_report

    try:
        token = read_token(token_file, output, graph_db)
        tenant_id = resolve_cli_tenant_id_strict(tenant)
        report = collect_report(team_id=team_id, token=token)
        report["scan_id"] = str(uuid4())
        report["persistence"] = {
            "graph": "not_requested" if graph_db is None else "pending" if report["status"] == "ok" else "skipped_incomplete"
        }
        _write_report(output, report)
        if graph_db is not None and report["status"] == "ok":
            persist_graph(report, graph_db, tenant_id, output, scope_entity_types={"account"}, scope_node_ids={"account:vercel:" + team_id})
        if push_url:
            push_report(report, push_url, push_api_key, output)
    except CollectionScopeMismatchError as exc:
        raise click.ClickException("Collection scope changed; use a separate graph database") from exc
    except ConnectorPushError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(sanitize_error(exc, generic=True)) from exc
    inventory = report["cloud_inventory"][0]
    click.echo(
        f"Vercel: {report['status']}; {len(inventory['projects'])} projects; "
        f"{len(inventory['deployments'])} deployments; {len(report['findings'])} configuration findings."
    )
    click.echo(f"Report: {output}. Inventory completeness does not establish clean posture.")
    if report["status"] != "ok":
        raise click.exceptions.Exit(2)
