"""Cytoscape nodes and edges for framework-native agents (LangGraph, CrewAI, AutoGen, Agents SDK).

Draws what ``ai_inventory.framework_agents`` already records, with the node ids
the unified graph uses: each agent under its ``stable_id``, its framework as a
``framework`` node, and the topology edges (``delegated_to``, ``shares_server``)
the source scanner found. No topology is inferred here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.graph.node import stable_node_id
from agent_bom.graph.types import EntityType
from agent_bom.security import sanitize_text

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport

_MAX_AGENTS = 2_000


def _text(value: Any, max_len: int = 200) -> str:
    return sanitize_text(str(value or ""), max_len=max_len).strip()


def _framework_id(name: str) -> str:
    return stable_node_id(EntityType.FRAMEWORK.value, name.strip().lower() or "unknown")


class _Elements:
    def __init__(self, elements: list[dict]) -> None:
        self.elements = elements
        self.nodes = {str(el["data"]["id"]) for el in elements if "id" in el.get("data", {})}
        self.edges = {
            (str(el["data"]["source"]), str(el["data"]["target"]), str(el["data"].get("type", "")))
            for el in elements
            if "source" in el.get("data", {}) and "target" in el.get("data", {})
        }

    def node(self, data: dict[str, Any]) -> None:
        if data["id"] not in self.nodes:
            self.nodes.add(data["id"])
            self.elements.append({"data": data})

    def edge(self, source: str, target: str, kind: str, **extra: Any) -> None:
        key = (source, target, kind)
        if key not in self.edges and source in self.nodes and target in self.nodes:
            self.edges.add(key)
            self.elements.append({"data": {"source": source, "target": target, "type": kind, **extra}})

    def framework(self, name: str) -> str | None:
        if not name:
            return None
        fid = _framework_id(name)
        self.node({"id": fid, "label": name, "type": "framework", "tip": f"Agent framework: {name}", "searchText": name.lower()})
        return fid


def _agent_node(item: dict[str, Any], agent_id: str) -> dict[str, Any]:
    name = _text(item.get("name")) or agent_id
    framework = _text(item.get("framework"), 100)
    source_file = _text(item.get("file_path"), 500).replace("\\", "/")
    line = item.get("line_number") if isinstance(item.get("line_number"), int) else None
    location = f"{source_file}:{line}" if source_file and line else source_file
    return {
        "id": agent_id,
        "label": name,
        "type": "agent",
        "agentType": "framework-agent",
        "framework": framework,
        "sourceFile": source_file,
        "line": line,
        "discovery_source": "source-ast",
        "tip": f"Framework agent: {name}\nFramework: {framework}" + (f"\nSource: {location}" if location else ""),
        "searchText": f"{name} {framework} {source_file}".lower(),
    }


def append_framework_agent_elements(elements: list[dict], report: "AIBOMReport") -> None:
    """Append framework agents, their frameworks and their static topology edges."""
    inventory = report.ai_inventory_data
    raw = inventory.get("framework_agents") if isinstance(inventory, dict) else None
    if not isinstance(raw, list) or not raw:
        return
    items = [item for item in raw[:_MAX_AGENTS] if isinstance(item, dict) and _text(item.get("stable_id"), 100)]
    out = _Elements(elements)
    for item in items:
        agent_id = _text(item.get("stable_id"), 100)
        out.node(_agent_node(item, agent_id))
        fid = out.framework(_text(item.get("framework"), 100))
        if fid:
            out.edge(agent_id, fid, "uses_framework")
    for item in items:
        for edge in item.get("topology_edges") or []:
            if not isinstance(edge, dict):
                continue
            source, target = _text(edge.get("source_id"), 100), _text(edge.get("target_id"), 100)
            relationship = _text(edge.get("relationship"), 50) or "delegated_to"
            if not source or not target:
                continue
            for node_id, name in ((source, edge.get("source_name")), (target, edge.get("target_name"))):
                if node_id not in out.nodes:
                    out.node(_agent_node({"name": name, "framework": edge.get("framework")}, node_id))
            out.edge(
                source,
                target,
                relationship,
                evidence=_text(edge.get("evidence"), 200),
                line=edge.get("line_number") if isinstance(edge.get("line_number"), int) else None,
            )
