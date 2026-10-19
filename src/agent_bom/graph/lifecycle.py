"""Agent lifecycle view over the shared inventory graph, including its evidence."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any, Iterable, Mapping

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


def _with_blast_advisories(agent: dict[str, Any], blast_rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Attach the agent detail's advisory rows to the inventory packages they name.

    Stored agent inventory keeps package vulnerabilities out of the package
    records; the detail's blast-radius rows are the same evidence the findings
    and graph count. A row lands on a package only when name, version and
    ecosystem match and, when it names servers, the server matches too.
    """
    rows = [row for row in blast_rows if row.get("vulnerability_id") and row.get("package_name")]
    if not rows:
        return agent
    joined = deepcopy(agent)
    for server in joined.get("mcp_servers") or []:
        for package in server.get("packages") or []:
            known = {str(vuln.get("id") or "") for vuln in package.get("vulnerabilities") or []}
            for row in rows:
                servers = row.get("affected_servers") or []
                if (
                    row.get("package_name") != package.get("name")
                    or str(row.get("package_version") or "") != str(package.get("version") or "")
                    or (row.get("ecosystem") and package.get("ecosystem") and row["ecosystem"] != package["ecosystem"])
                    or (servers and server.get("name") not in servers)
                    or row["vulnerability_id"] in known
                ):
                    continue
                known.add(row["vulnerability_id"])
                package.setdefault("vulnerabilities", []).append(
                    {
                        "id": row["vulnerability_id"],
                        "severity": str(row.get("severity") or ""),
                        "cvss_score": row.get("cvss_score"),
                        "fixed_version": row.get("fixed_version"),
                        "summary": str(row.get("ai_summary") or ""),
                    }
                )
    return joined


def agent_lifecycle_view(agent: dict[str, Any], *, tenant_id: str, blast_radius: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Project one selected agent without guessing execution, access, or a scan ID.

    The canonical graph owns identity, deduplication, direction and receipts.
    Legacy React Flow envelopes remain available to older clients. Counts name
    unique visible entities; a shared advisory is counted once even when several
    package relationships lead to it. No tool or edge is silently truncated.
    """
    graph = UnifiedGraph(tenant_id=tenant_id)
    project_agents(graph, [_with_blast_advisories(agent, blast_radius)], "mcp-scan", _add_agent_cloud_lineage)
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
