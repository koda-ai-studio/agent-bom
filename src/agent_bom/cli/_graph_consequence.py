"""JSON consequence export using the authenticated control-plane client."""

from __future__ import annotations

import click
from pydantic import ValidationError

from agent_bom.cli._findings_group import _common_api_options, _emit_json, _make_client, _run_request
from agent_bom.graph.consequence.contracts import ConsequenceRequest


@click.command("consequences")
@click.option("--node", "root_node_id", required=True)
@click.option("--scan-id", required=True)
@click.option("--mode", type=click.Choice(["vulnerability", "assumed_compromise"]), required=True)
@click.option("--assume-control", is_flag=True, help="Explicit hypothetical control of the selected agent or principal.")
@click.option("--affected-node", "affected_node_id", help="Occurrence linked to a vulnerability root.")
@click.option("--snapshot-generation", help="Require this immutable revision.")
@click.option("--max-depth", type=click.IntRange(1, 10), default=6, show_default=True)
@click.option("--max-results", type=click.IntRange(1, 512), default=128, show_default=True)
@_common_api_options
def consequences_cmd(
    api_url,
    api_key,
    bearer_token,
    tenant_id,
    root_node_id,
    scan_id,
    mode,
    assume_control,
    affected_node_id,
    snapshot_generation,
    max_depth,
    max_results,
) -> None:
    """Export experimental action consequences and evidence gaps as JSON."""

    try:
        request = ConsequenceRequest(
            root_node_id=root_node_id,
            mode=mode,
            assume_control=assume_control,
            affected_node_id=affected_node_id,
            max_depth=max_depth,
            max_results=max_results,
        )
    except ValidationError as exc:
        raise click.UsageError("Use --assume-control for an agent/principal, or --affected-node with vulnerability mode.") from exc
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    result = _run_request(
        client,
        lambda api: api.consequence_assessment(
            request=request.model_dump(mode="json"), scan_id=scan_id, snapshot_generation=snapshot_generation
        ),
    )
    _emit_json(result)
