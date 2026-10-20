"""Showcase fleet shared by demo bootstrap and graph projections."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.demo_estate.showcase_constants import SHOWCASE_TENANT


def seed_showcase_fleet_and_runtime(tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Populate the LIVE fleet and MCP-observation stores from the estate.

    ``/v1/agent-bom/manifest`` — the AI BOM page — is built from exactly two
    stores: the fleet registry and the MCP observation store. The demo bootstrap
    seeded the graph, the findings and the identities, but never those two, so
    the AI BOM read **0 agents / 0 MCP servers / 0 tools** on an estate holding
    48 agents, 25 servers and 97 tools. The page's own promise is "live
    inventory from connected agents… not a static upload", and it was showing
    nothing at all.

    Same contract as :func:`seed_showcase_identities`: idempotent, independent
    of the graph seed, and only ever under demo-estate mode, so a restart or an
    already-seeded graph still leaves the AI BOM populated. Older synthetic
    association revisions are refreshed once so fleet counts and graph links
    agree; non-demo fleet records are not rewritten.
    """
    from agent_bom.api.stores import _get_fleet_store, _get_mcp_observation_store
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate

    fleet_store = _get_fleet_store()
    observation_store = _get_mcp_observation_store()
    association_revision = "demo-associations-v3"
    existing = [a for a in fleet_store.list_by_tenant(tenant_id) if a.agent_id.startswith("demo-fleet-")]
    if existing and all(association_revision in a.tags for a in existing):
        return {"seeded": False, "reason": "fleet_present"}

    estate = build_demo_estate(tenant_id=tenant_id)
    by_type: dict[str, list[Any]] = {}
    for asset in estate.assets:
        by_type.setdefault(asset.resource_type, []).append(asset)

    servers = by_type.get("server", [])
    tools_by_server: dict[str, list[Any]] = {}
    for tool in by_type.get("tool", []):
        tools_by_server.setdefault(str(tool.tags.get("mcp_server") or ""), []).append(tool)

    now = datetime.now(timezone.utc).isoformat()
    agents = by_type.get("agent", [])
    server_ids = {asset.asset_id for asset in servers}
    agents_by_server: dict[str, list[str]] = {}
    for agent in agents:
        target = agent.tags.get("uses_server", "")
        if target in server_ids:
            agents_by_server.setdefault(target, []).append(agent.asset_id)
    _seed_fleet_agents(fleet_store, agents, server_ids, association_revision, tenant_id, now)
    _seed_observations(observation_store, servers, agents, tools_by_server, agents_by_server, tenant_id, now)

    return {
        "seeded": True,
        "fleet_agents": len(agents),
        "mcp_observations": sum(max(1, len(agents_by_server.get(server.asset_id, []))) for server in servers),
        "tools": sum(len(v) for v in tools_by_server.values()),
    }


def _seed_fleet_agents(
    fleet_store: Any, agents: list[Any], server_ids: set[str], association_revision: str, tenant_id: str, now: str
) -> None:
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState

    for index, asset in enumerate(agents):
        # Deterministic spread so the fleet reads like a managed estate rather
        # than one uniform block. A real fleet is mostly approved with a tail of
        # in-flight and problem agents; every row in one state is the tell that
        # nothing is actually being governed.
        bucket = index % 10
        if bucket == 0:
            state = FleetLifecycleState.QUARANTINED
        elif bucket in (1, 2):
            state = FleetLifecycleState.PENDING_REVIEW
        elif bucket == 3:
            state = FleetLifecycleState.DISCOVERED
        else:
            state = FleetLifecycleState.APPROVED
        fleet_store.put(
            FleetAgent(
                agent_id=f"demo-fleet-{asset.asset_id}",
                name=asset.display_name,
                agent_type=str(asset.tags.get("agent_framework") or "mcp-client"),
                lifecycle_state=state,
                owner=str(asset.tags.get("owner") or "platform-engineering"),
                environment=asset.environment or "production",
                tags=[t for t in (asset.environment, asset.provider, association_revision) if t],
                trust_score=round(0.55 + ((index % 9) / 20.0), 2),
                server_count=int(asset.tags.get("uses_server", "") in server_ids),
                tenant_id=tenant_id,
                last_discovery=now,
                last_scan=now,
                created_at=now,
                updated_at=now,
            )
        )


def _seed_observations(
    observation_store: Any,
    servers: list[Any],
    agents: list[Any],
    tools_by_server: dict[str, list[Any]],
    agents_by_server: dict[str, list[str]],
    tenant_id: str,
    now: str,
) -> None:
    from agent_bom.api.mcp_observation_store import MCPObservation

    for index, asset in enumerate(servers):
        tools = tools_by_server.get(asset.asset_id, [])
        source_ids = sorted(agents_by_server.get(asset.asset_id, []))
        source_agents = sorted(agent.display_name for agent in agents if agent.asset_id in source_ids)
        for subject_id in source_ids or [""]:
            observation_store.put(
                MCPObservation(
                    tenant_id=tenant_id,
                    observation_id=f"demo-obs-{asset.asset_id}:{subject_id}",
                    agent_id=f"demo-fleet-{subject_id}" if subject_id else "",
                    server_stable_id=asset.asset_id,
                    server_name=asset.display_name,
                    agent_name=source_agents[0] if source_agents else "",
                    transport=str(asset.tags.get("transport") or "streamable-http"),
                    url=asset.native_id if str(asset.native_id).startswith("http") else None,
                    auth_mode=str(asset.tags.get("auth_mode") or "bearer"),
                    credential_env_vars=[],
                    observed_via=["demo-estate"],
                    scan_sources=["demo-estate"],
                    source_agents=source_agents,
                    configured_locally=False,
                    fleet_present=True,
                    gateway_registered=index % 3 != 0,
                    runtime_observed=index % 4 != 0,
                    observed_scopes=sorted({str(t.tags.get("scope") or "read") for t in tools}) or ["read"],
                    first_seen=now,
                    last_seen=now,
                )
            )
