"""Snowflake Cortex Agent projection: declared tools, execution roles, observed telemetry.

One AGENT node per Cortex Agent, keyed by
:func:`agent_bom.canonical_ids.snowflake_cortex_agent_node_id` — the same id the
discovery inventory and usage history resolve to. The id already carries the
account, so the node and its tools are exempt from per-account rescoping.

Cortex Agents take permissions from the request's Snowflake context (the
caller's role), not from the owner. The roles granted USAGE or OWNERSHIP on an
agent are therefore modeled as the roles it can execute as (``ASSUMES``).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agent_bom.canonical_ids import snowflake_cortex_agent_node_id, snowflake_cortex_tool_node_id, snowflake_stored_fqn
from agent_bom.graph.builder_snowflake_lane import _snowflake_thin_node, _SnowflakeLane
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part

CORTEX_SOURCE = "snowflake-cortex-agents"
TELEMETRY_SOURCE = "snowflake-cortex-observability"
_RESOURCE_NODES: dict[str, tuple[str, EntityType, str]] = {
    "semantic_view": ("data_store:snowflake:{fqn}", EntityType.DATA_STORE, "data"),
    "stage": ("cloud_resource:snowflake:stage:{fqn}", EntityType.CLOUD_RESOURCE, "data"),
    "cortex_search_service": ("cloud_resource:snowflake:cortex_search_service:{fqn}", EntityType.CLOUD_RESOURCE, "ai"),
    "function": ("cloud_resource:snowflake:function:{fqn}", EntityType.CLOUD_RESOURCE, "compute"),
    "procedure": ("cloud_resource:snowflake:procedure:{fqn}", EntityType.CLOUD_RESOURCE, "compute"),
    "warehouse": ("cloud_resource:snowflake:warehouse:{fqn}", EntityType.CLOUD_RESOURCE, "compute"),
}


def _qualified_attrs(account: str) -> dict[str, Any]:
    return {"account_id": account, "snowflake_account_qualified": True} if account else {}


def _agent_id(account: str, agent: dict[str, Any]) -> str:
    return snowflake_cortex_agent_node_id(account, agent.get("database"), agent.get("schema"), agent.get("name"))


def _add_agent(lane: _SnowflakeLane, account: str, agent: dict[str, Any]) -> str:
    agent_id = _agent_id(account, agent)
    fqn = snowflake_stored_fqn(agent.get("database"), agent.get("schema"), agent.get("name"))
    tools = [tool for tool in agent.get("tools") or [] if isinstance(tool, dict)]
    lane.graph.add_node(
        UnifiedNode(
            id=agent_id,
            entity_type=EntityType.AGENT,
            label=f"cortex agent: {fqn}",
            attributes={
                "cloud_provider": "snowflake",
                "snowflake_fqn": fqn,
                "cortex_agent_owner": _clean_graph_part(agent.get("owner")),
                "cortex_spec_status": _clean_graph_part(agent.get("spec_status")) or "unavailable",
                "is_secure": bool(agent.get("is_secure")),
                "declared_tools": sorted(_clean_graph_part(tool.get("name")) for tool in tools),
                "execution_model": "caller_role",
                **_qualified_attrs(account),
            },
            data_sources=lane.data_sources,
            dimensions=NodeDimensions(cloud_provider="snowflake", surface="ai"),
        )
    )
    if lane.account_node_id:
        _add_rel_edge(lane.graph, lane.account_node_id, agent_id, RelationshipType.OWNS, {"source": CORTEX_SOURCE})
    for tool in tools:
        _add_tool(lane, account, agent_id, agent, tool)
    for grant in agent.get("execution_roles") or []:
        role = _clean_graph_part(grant.get("role")) if isinstance(grant, dict) else ""
        if not role:
            continue
        role_id = f"role:snowflake:{role}"
        _snowflake_thin_node(lane, role_id, EntityType.ROLE, f"role: {role}", "identity")
        evidence = {
            "source": CORTEX_SOURCE,
            "basis": "agent_grant_caller_context",
            "privilege": _clean_graph_part(grant.get("privilege")),
            "execution_model": "caller_role",
        }
        _add_rel_edge(lane.graph, agent_id, role_id, RelationshipType.ASSUMES, evidence)
    return agent_id


def _add_tool(lane: _SnowflakeLane, account: str, agent_id: str, agent: dict[str, Any], tool: dict[str, Any]) -> None:
    name = _clean_graph_part(tool.get("name"))
    if not name:
        return
    tool_id = snowflake_cortex_tool_node_id(agent_id, agent.get("name"), name)
    lane.graph.add_node(
        UnifiedNode(
            id=tool_id,
            entity_type=EntityType.TOOL,
            label=name,
            attributes={
                "cloud_provider": "snowflake",
                "cortex_tool_type": _clean_graph_part(tool.get("type")),
                **_qualified_attrs(account),
            },
            data_sources=lane.data_sources,
            dimensions=NodeDimensions(cloud_provider="snowflake", surface="ai"),
        )
    )
    _add_rel_edge(lane.graph, agent_id, tool_id, RelationshipType.REACHES_TOOL, {"source": CORTEX_SOURCE, "basis": "agent_spec_tools"})
    for resource in tool.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        kind = _clean_graph_part(resource.get("kind"))
        fqn = _clean_graph_part(resource.get("fqn"))
        template = _RESOURCE_NODES.get(kind)
        if not template or not fqn:
            continue
        node_template, entity_type, surface = template
        target_id = node_template.format(fqn=fqn)
        _snowflake_thin_node(lane, target_id, entity_type, f"{kind.replace('_', ' ')}: {fqn}", surface)
        evidence = {"source": CORTEX_SOURCE, "basis": "agent_spec_tool_resources", "resource_kind": kind}
        _add_rel_edge(lane.graph, tool_id, target_id, RelationshipType.CAN_ACCESS, evidence)


def add_cortex_agents(lane: _SnowflakeLane, account: str, agents: Any) -> dict[tuple[str, str, str], str]:
    """Project DESCRIBE AGENT specifications; returns ``(database, schema, name) -> node id``."""
    by_name: dict[tuple[str, str, str], str] = {}
    for agent in agents or []:
        if not isinstance(agent, dict) or not all(_clean_graph_part(agent.get(key)) for key in ("database", "schema", "name")):
            continue
        key = (_clean_graph_part(agent["database"]), _clean_graph_part(agent["schema"]), _clean_graph_part(agent["name"]))
        by_name[key] = _add_agent(lane, account, agent)
    return by_name


def _telemetry_targets(event: dict[str, Any]) -> list[tuple[str, EntityType, str, RelationshipType]]:
    targets: list[tuple[str, EntityType, str, RelationshipType]] = []
    node_id = _clean_graph_part(event.get("match_node_id"))
    if event.get("match_method") == "exact" and node_id.startswith("tool:"):
        targets.append((node_id, EntityType.TOOL, "", RelationshipType.INVOKED))
    for ref in event.get("resource_refs") or []:
        kind, _, name = str(ref).partition(":")
        if kind == "warehouse" and name:
            targets.append((f"cloud_resource:snowflake:warehouse:{name}", EntityType.CLOUD_RESOURCE, "compute", RelationshipType.ACCESSED))
    role = _clean_graph_part(event.get("role_name"))
    if role:
        targets.append((f"role:snowflake:{role}", EntityType.ROLE, "identity", RelationshipType.ASSUMES))
    return targets


def _bump(stats: dict[str, Any], event: dict[str, Any]) -> None:
    stats["count"] += 1
    for stamp in (event.get("started_at"), event.get("ended_at")):
        if stamp:
            stats["first_seen"] = min(filter(None, (stats["first_seen"], stamp)))
            stats["last_seen"] = max(filter(None, (stats["last_seen"], stamp)))
    if event.get("status") == "error":
        stats["error_count"] += 1
    if event.get("principal_hash"):
        stats["principals"].add(event["principal_hash"])
    if event.get("source_trace_id"):
        stats["traces"].add(event["source_trace_id"])


def add_cortex_telemetry(lane: _SnowflakeLane, events: Any, agent_ids: set[str]) -> dict[str, int]:
    """Aggregate normalized observability events into one runtime edge per (agent, target, relationship).

    Only exact matches attach: an event whose agent is not a projected Cortex
    Agent, or whose tool is not declared by that agent, is counted, not guessed.
    """
    aggregates: dict[tuple[str, str, RelationshipType], dict[str, Any]] = {}
    kinds: dict[str, tuple[EntityType, str]] = {}
    counts: dict[str, int] = defaultdict(int)
    unmatched_tools: dict[str, int] = defaultdict(int)
    for event in events or []:
        if not isinstance(event, dict):
            continue
        counts["events"] += 1
        agent_id = _clean_graph_part(event.get("agent_ref"))
        if agent_id not in agent_ids:
            counts["unmatched_agent"] += 1
            continue
        if event.get("tool_name") and event.get("match_method") != "exact":
            counts["unmatched_tool"] += 1
            unmatched_tools[agent_id] += 1
        for target_id, entity_type, surface, rel in _telemetry_targets(event):
            if rel is RelationshipType.INVOKED and target_id not in lane.graph.nodes:
                counts["unmatched_tool"] += 1
                unmatched_tools[agent_id] += 1
                continue
            kinds[target_id] = (entity_type, surface)
            stats = aggregates.setdefault(
                (agent_id, target_id, rel),
                {"count": 0, "error_count": 0, "first_seen": "", "last_seen": "", "principals": set(), "traces": set()},
            )
            _bump(stats, event)
            counts["matched"] += 1
    for (agent_id, target_id, rel), stats in aggregates.items():
        entity_type, surface = kinds[target_id]
        if surface:
            _snowflake_thin_node(lane, target_id, entity_type, target_id.rsplit(":", 1)[-1], surface)
        evidence = {
            "source": TELEMETRY_SOURCE,
            "basis": "cortex_observability_spans",
            # Nested so an observation merged onto a grant-derived edge stays distinct from it.
            "observed": {
                "source": TELEMETRY_SOURCE,
                "event_count": stats["count"],
                "error_count": stats["error_count"],
                "trace_count": len(stats["traces"]),
                "distinct_principals": len(stats["principals"]),
                "first_seen": stats["first_seen"],
                "last_seen": stats["last_seen"],
            },
        }
        _add_rel_edge(lane.graph, agent_id, target_id, rel, evidence)
    for agent_id in agent_ids:
        node = lane.graph.nodes.get(agent_id)
        if node is not None:
            node.attributes["cortex_telemetry"] = {
                "unmatched_tool_events": unmatched_tools.get(agent_id, 0),
                "observed_edges": sum(1 for key in aggregates if key[0] == agent_id),
            }
    return dict(counts)
