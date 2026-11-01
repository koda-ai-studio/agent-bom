"""Record which workload each cloud-hosted estate MCP server runs in.

The third-party lane generated MCP servers with an account and a host cloud but
no deployment, so the graph could not draw ``server -[hosted_on]-> workload`` and
no estate agent chained through a server to the image and packages beneath it.
This pass records a deployment for every server whose host cloud runs the
estate's Kubernetes workloads, as a labelled synthetic placement
(``placement_source``). A server is recorded where its workload runs: when no
workload shares its account and environment, the server and its tools are
placed in the chosen workload's account, region and environment, so a server
never claims to run in one account on a workload in another. Servers on a
platform without estate workloads (Snowflake) are left unplaced.
"""

from __future__ import annotations

from collections.abc import Sequence

from agent_bom.demo_estate.enterprise import EstateAsset
from agent_bom.demo_estate.enterprise_ai import stable_index

PLACEMENT_SOURCE = "synthetic-demo-placement"
_CONTAINER_HOSTS = frozenset({"aws", "azure", "gcp"})


def _choose_workload(server: EstateAsset, workloads: Sequence[EstateAsset], *, any_cloud: bool = False) -> EstateAsset | None:
    host = server.tags.get("host_provider", "")
    same_cloud = [w for w in workloads if any_cloud or w.tags.get("host_provider") == host]
    tiers = (
        [w for w in same_cloud if (w.account_scope, w.environment) == (server.account_scope, server.environment)],
        [w for w in same_cloud if w.account_scope == server.account_scope],
        [w for w in same_cloud if w.environment == server.environment],
        same_cloud,
    )
    candidates = next((tier for tier in tiers if tier), [])
    if not candidates:
        return None
    ordered = sorted(candidates, key=lambda w: w.asset_id)
    return ordered[stable_index("mcp-placement", server.asset_id) % len(ordered)]


def _placed(asset: EstateAsset, workload: EstateAsset, **tags: str) -> EstateAsset:
    return asset.model_copy(
        update={
            "account_scope": workload.account_scope,
            "region": workload.region,
            "environment": workload.environment,
            "tags": {**asset.tags, "environment": workload.environment, **tags},
        }
    )


def place_mcp_servers_on_workloads(third_party: Sequence[EstateAsset], delivery: Sequence[EstateAsset]) -> tuple[EstateAsset, ...]:
    """Return ``third_party`` with each container-hosted MCP server bound to one workload."""
    workloads = [asset for asset in delivery if asset.resource_type == "deployment"]
    placements: dict[str, EstateAsset] = {}
    for asset in third_party:
        if asset.resource_type == "server" and asset.tags.get("host_provider") in _CONTAINER_HOSTS:
            workload = _choose_workload(asset, workloads)
            if workload is not None:
                placements[asset.asset_id] = workload
    placed: list[EstateAsset] = []
    for asset in third_party:
        if asset.asset_id in placements:
            workload = placements[asset.asset_id]
            placed.append(_placed(asset, workload, deployment=workload.asset_id, placement_source=PLACEMENT_SOURCE))
        elif asset.resource_type == "tool" and asset.tags.get("mcp_server") in placements:
            placed.append(_placed(asset, placements[asset.tags["mcp_server"]]))
        else:
            placed.append(asset)
    return tuple(placed)


def place_agents_on_workloads(third_party: Sequence[EstateAsset], delivery: Sequence[EstateAsset]) -> tuple[EstateAsset, ...]:
    """Return ``third_party`` with each cloud-hosted agent bound to one workload and typed by its framework.

    An agent without a deployment has no execution context: the graph could say
    which platform it rides and which model it serves, but not where it runs or
    what kind of agent it is. The same labelled synthetic placement the MCP
    servers use gives every third-party agent a ``hosted_on`` workload in its
    own cloud, and ``agent_type`` names the recorded framework (or ``service``).
    """
    workloads = [asset for asset in delivery if asset.resource_type == "deployment"]
    placed: list[EstateAsset] = []
    for asset in third_party:
        if asset.resource_type != "agent":
            placed.append(asset)
            continue
        agent_type = asset.tags.get("agent_framework") or "service"
        # An agent on a platform without estate workloads is re-homed to a cloud that has
        # them, host provider included, so the recorded host is never in another cloud.
        workload = _choose_workload(asset, workloads) or _choose_workload(asset, workloads, any_cloud=True)
        if workload is None:
            placed.append(asset.model_copy(update={"tags": {**asset.tags, "agent_type": agent_type}}))
            continue
        host_provider = workload.tags.get("host_provider", asset.tags.get("host_provider", ""))
        placed.append(
            _placed(
                asset,
                workload,
                deployment=workload.asset_id,
                placement_source=PLACEMENT_SOURCE,
                agent_type=agent_type,
                host_provider=host_provider,
            )
        )
    return tuple(placed)


def place_on_workloads(third_party: Sequence[EstateAsset], delivery: Sequence[EstateAsset]) -> tuple[EstateAsset, ...]:
    """Servers first (their tools follow them), then agents: the whole third-party lane with a place to run."""
    return place_agents_on_workloads(place_mcp_servers_on_workloads(third_party, delivery), delivery)


__all__ = ["PLACEMENT_SOURCE", "place_agents_on_workloads", "place_mcp_servers_on_workloads", "place_on_workloads"]
