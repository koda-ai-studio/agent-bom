"""Expose the existing MCP capability scorer on graph assets, with bounded provenance."""

from __future__ import annotations

from agent_bom import risk_analyzer
from agent_bom.domain.mcp_model import MCPTool
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _record(node: UnifiedNode, score: float, level: str, basis: str, justification: str, capabilities: object) -> None:
    scope = "loaded_mcp_capabilities_and_credential_references"
    node.attributes["capability_risk"] = {
        "score": round(score, 2),
        "level": level,
        "basis": basis,
        "scope": scope,
        "justification": justification,
        "capabilities": capabilities,
    }
    # Capability is an independent assessment, not the graph risk used for ranking and paging.


def apply_mcp_risk(graph: UnifiedGraph) -> None:
    """Score known tools and recorded server memberships; missing inventory stays unknown.

    Capability heuristics are a prioritization signal, not proof of execution,
    credential theft, or completeness of the scanned server's inventory.
    """
    if not any(node.entity_type in {EntityType.TOOL, EntityType.SERVER} for node in graph.nodes.values()):
        return

    tools = {}
    for node in graph.iter_nodes_by_type(EntityType.TOOL):
        attrs = node.attributes
        declared = _strings(attrs.get("declared_capabilities"))
        if not declared and attrs.get("tool_class") == "shell":
            declared = ["execute"]
        model = MCPTool(
            name=node.label,
            description=str(attrs.get("description") or ""),
            declared_capabilities=declared,
            schema_findings=_strings(attrs.get("schema_findings")),
        )
        profile = risk_analyzer.score_tool_risk(model)
        if not profile.capabilities and not model.schema_findings:
            continue
        tools[node.id] = model
        basis = "mcp_capability_risk_declared" if declared else "mcp_capability_risk_inferred_from_descriptor"
        _record(node, profile.risk_score, profile.risk_level, basis, profile.justification, profile.capabilities)
    for node in graph.nodes.values():
        if node.entity_type not in {EntityType.SERVER}:
            continue
        links = [
            edge
            for edge in graph.adjacency.get(node.id, [])
            if edge.evidence.get("tier") in {"static_scan", "recorded", "runtime_observed"}
        ]
        members = sorted({edge.target for edge in links if edge.relationship == RelationshipType.PROVIDES_TOOL and edge.target in tools})
        credentials = sorted(
            {
                edge.target
                for edge in links
                if edge.relationship == RelationshipType.EXPOSES_CRED
                and (target := graph.get_node(edge.target)) is not None
                and target.entity_type == EntityType.CREDENTIAL
            }
        )
        if not members and not credentials:
            continue
        server_profile = risk_analyzer.score_server_risk([tools[key] for key in members], credentials=credentials)
        _record(
            node,
            server_profile.risk_score,
            server_profile.risk_level,
            "mcp_capability_portfolio_risk",
            server_profile.justification,
            server_profile.capabilities,
        )
