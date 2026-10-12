"""JSON consequence export using the authenticated control-plane client."""

from __future__ import annotations

import click

from agent_bom.cli._findings_group import _common_api_options, _emit_json, _make_client, _run_request


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

    if (mode == "assumed_compromise" and (not assume_control or affected_node_id is not None)) or (
        mode == "vulnerability" and (assume_control or not affected_node_id)
    ):
        raise click.UsageError("Use --assume-control for an agent/principal, or --affected-node with vulnerability mode.")
    request = {
        "root_node_id": root_node_id,
        "mode": mode,
        "assume_control": assume_control,
        "affected_node_id": affected_node_id,
        "max_depth": max_depth,
        "max_results": max_results,
    }
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    result = _run_request(
        client,
        lambda api: api.consequence_assessment(request=request, scan_id=scan_id, snapshot_generation=snapshot_generation),
    )
    _emit_json(result)
