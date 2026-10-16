"""Agent lifecycle view over the shared inventory graph, including its evidence."""

from __future__ import annotations

from collections import Counter
from typing import Any

from agent_bom.graph.agent_projection import project_agents
from agent_bom.graph.asset_canonicalize import canonicalize_assets
from agent_bom.graph.builder import _add_agent_cloud_lineage
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType

_LANES = {
    EntityType.AGENT: ("agent", 0),
    EntityType.SERVER: ("server", 1),
    EntityType.TOOL: ("tool", 2),
    EntityType.CREDENTIAL: ("credential", 2),
    EntityType.PACKAGE: ("package", 3),
    EntityType.VULNERABILITY: ("cve", 4),
}


def agent_lifecycle_view(agent: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    """Project one selected agent without guessing execution, access, or a scan ID.

    The canonical graph owns identity, deduplication, direction and receipts.
    Legacy React Flow envelopes remain available to older clients. Counts name
    unique visible entities; a shared advisory is counted once even when several
    package relationships lead to it. No tool or edge is silently truncated.
    """
    graph = UnifiedGraph(tenant_id=tenant_id)
    project_agents(graph, [agent], "mcp-scan", _add_agent_cloud_lineage)
    canonicalize_assets(graph)
    nodes: list[dict[str, Any]] = []
    lanes: Counter[int] = Counter()
    types: Counter[EntityType] = Counter()
    severities: Counter[str] = Counter()
    for node in sorted(graph.nodes.values(), key=lambda item: item.id):
        if node.entity_type not in _LANES:
            continue
        kind, lane = _LANES[node.entity_type]
        attrs = node.attributes
        nodes.append(
            {
                "id": node.id,
                "type": "lifecycleNode",
                "position": {"x": lane * 350, "y": lanes[lane] * 100},
                "data": {
                    **attrs,
                    "nodeType": kind,
                    "label": node.label,
                    "severity": node.severity,
                    "entity_type": node.entity_type.value,
                    "source_receipt": node.to_dict(),
                },
            }
        )
        lanes[lane] += 1
        types[node.entity_type] += 1
        if node.entity_type == EntityType.VULNERABILITY:
            severity = str(node.severity or "").lower()
            severities[severity if severity in {"critical", "high", "medium", "low"} else "unrated"] += 1
    visible = {node["id"] for node in nodes}
    edges = [
        {
            "id": edge.id,
            "source": edge.source,
            "target": edge.target,
            "type": "smoothstep",
            "label": edge.relationship.value.replace("_", " "),
            "data": edge.to_dict(),
        }
        for edge in graph.edges
        if edge.source in visible and edge.target in visible
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "graph": graph.to_dict(),
        "stats": {
            "total_servers": types[EntityType.SERVER],
            "total_packages": types[EntityType.PACKAGE],
            "total_tools": types[EntityType.TOOL],
            "total_credentials": types[EntityType.CREDENTIAL],
            "total_vulnerabilities": types[EntityType.VULNERABILITY],
            "severity_breakdown": {key: severities[key] for key in ("critical", "high", "medium", "low", "unrated")},
        },
    }
