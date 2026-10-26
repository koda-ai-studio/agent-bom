"""Framework topology projection."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode, stable_node_id
from agent_bom.graph.training_projection import _model_node_id
from agent_bom.graph.types import EntityType, RelationshipType


def _add_framework_topology(
    graph: UnifiedGraph,
    framework_agents: Any,
    data_source: str,
    *,
    host_agent_id: str | None = None,
) -> None:
    """Add framework nodes, model nodes, framework-native agents, and topology edges.

    Frameworks (LangChain, LangGraph, CrewAI, …) are first-class BOM entities.
    Agents link via ``uses_framework``; model string refs become ``model`` nodes
    linked via ``serves_model``.

    With a ``host_agent_id`` (the project agent), a construct that takes no part
    in multi-agent delegation is folded into the host as ``code_agents``
    evidence; delegation participants remain distinct agents.
    """
    if not isinstance(framework_agents, list):
        return
    projection = _FrameworkTopology(graph, data_source, host_agent_id, framework_agents)
    for item in framework_agents:
        projection.project_agent(item)
    if projection.host is not None and projection.folded:
        projection.host.attributes["code_agents"] = projection.folded
        projection.host.data_sources = list(dict.fromkeys([*projection.host.data_sources, "source-ast"]))
    for item in framework_agents:
        projection.project_edges(item)


class _FrameworkTopology:
    """Per-build framework identity, folding and delegation projection."""

    def __init__(self, graph: UnifiedGraph, data_source: str, host_agent_id: str | None, framework_agents: list[Any]) -> None:
        self.graph = graph
        self.data_source = data_source
        self.known_agent_ids: set[str] = set()
        self.topology_participants: set[str] = set()
        self.host = graph.nodes.get(host_agent_id) if host_agent_id else None
        self.folded: list[dict[str, Any]] = []
        self.framework_ids: dict[str, str] = {}
        for item in framework_agents:
            if not isinstance(item, dict):
                continue
            for edge in item.get("topology_edges", []) or []:
                if isinstance(edge, dict):
                    self.topology_participants.add(str(edge.get("source_id") or "").strip())
                    self.topology_participants.add(str(edge.get("target_id") or "").strip())

    def _framework_node_id(self, name: str) -> str:
        key = name.strip().lower() or "unknown"
        if key not in self.framework_ids:
            self.framework_ids[key] = stable_node_id(EntityType.FRAMEWORK.value, key)
        return self.framework_ids[key]

    def _ensure_framework(self, name: str, *, kind: str = "orchestration") -> str | None:
        label = str(name or "").strip()
        if not label:
            return None
        fid = self._framework_node_id(label)
        if not self.graph.has_node(fid):
            self.graph.add_node(
                UnifiedNode(
                    id=fid,
                    entity_type=EntityType.FRAMEWORK,
                    label=label,
                    attributes={
                        "framework": label,
                        "framework_kind": kind,
                    },
                    dimensions=NodeDimensions(surface=label, agent_type="framework"),
                    data_sources=[self.data_source, "source-ast"],
                )
            )
        return fid

    def _ensure_model(self, ref: str) -> str | None:
        label = str(ref or "").strip()
        if not label:
            return None
        mid = _model_node_id(label)
        # add_node is create-or-merge: unconditionally add so a model discovered
        # by multiple sources (provenance + framework ref) unions its attributes
        # onto one node rather than being skipped when already present.
        self.graph.add_node(
            UnifiedNode(
                id=mid,
                entity_type=EntityType.MODEL,
                label=label,
                attributes={"model_ref": label, "source": "framework-agent"},
                dimensions=NodeDimensions(surface="model"),
                data_sources=[self.data_source, "source-ast"],
            )
        )
        return mid

    def project_agent(self, item: Any) -> None:
        if not isinstance(item, dict):
            return
        agent_id = str(item.get("stable_id") or "").strip()
        if not agent_id:
            return
        framework_name = str(item.get("framework") or "").strip()
        if self.host is not None and agent_id not in self.topology_participants:
            self.folded.append(
                {
                    "name": str(item.get("name") or agent_id),
                    "framework": framework_name,
                    "file_path": item.get("file_path", ""),
                    "line_number": item.get("line_number", 0),
                    "confidence": item.get("confidence", ""),
                    "capabilities": item.get("capabilities", []),
                    **_nesting_attributes(item),
                }
            )
            agent_id = self.host.id
        else:
            self.known_agent_ids.add(agent_id)
            self.graph.add_node(
                UnifiedNode(
                    id=agent_id,
                    entity_type=EntityType.AGENT,
                    label=str(item.get("name") or agent_id),
                    attributes={
                        "agent_type": "framework-agent",
                        "framework": framework_name,
                        "file_path": item.get("file_path", ""),
                        "line_number": item.get("line_number", 0),
                        "confidence": item.get("confidence", ""),
                        "model_refs": item.get("model_refs", []),
                        "credential_refs": item.get("credential_refs", []),
                        "capabilities": item.get("capabilities", []),
                        "dynamic_edges": item.get("dynamic_edges", False),
                        **_nesting_attributes(item),
                    },
                    dimensions=NodeDimensions(agent_type="framework-agent", surface=framework_name),
                    data_sources=[self.data_source, "source-ast"],
                )
            )
        fw_id = self._ensure_framework(framework_name)
        if fw_id:
            self.graph.add_edge(
                UnifiedEdge(
                    source=agent_id,
                    target=fw_id,
                    relationship=RelationshipType.USES_FRAMEWORK,
                    evidence={"source": "source-ast", "framework": framework_name},
                )
            )
        for model_ref in item.get("model_refs", []) or []:
            mid = self._ensure_model(str(model_ref))
            if mid:
                self.graph.add_edge(
                    UnifiedEdge(
                        source=agent_id,
                        target=mid,
                        relationship=RelationshipType.SERVES_MODEL,
                        evidence={"source": "source-ast", "model_ref": str(model_ref)},
                    )
                )

    def project_edges(self, item: Any) -> None:
        if not isinstance(item, dict):
            return
        for edge in item.get("topology_edges", []):
            if not isinstance(edge, dict):
                continue
            source_id = str(edge.get("source_id") or "").strip()
            target_id = str(edge.get("target_id") or "").strip()
            if not source_id or not target_id:
                continue
            for node_id, node_name in ((source_id, edge.get("source_name")), (target_id, edge.get("target_name"))):
                if node_id in self.known_agent_ids or self.graph.has_node(node_id):
                    continue
                edge_fw = str(edge.get("framework") or "").strip()
                self.graph.add_node(
                    UnifiedNode(
                        id=node_id,
                        entity_type=EntityType.AGENT,
                        label=str(node_name or node_id),
                        attributes={
                            "agent_type": "framework-agent",
                            "framework": edge_fw,
                            "synthetic_from_topology_edge": True,
                        },
                        dimensions=NodeDimensions(agent_type="framework-agent", surface=edge_fw),
                        data_sources=[self.data_source, "source-ast"],
                    )
                )
                self.known_agent_ids.add(node_id)
                fw_id = self._ensure_framework(edge_fw)
                if fw_id:
                    self.graph.add_edge(
                        UnifiedEdge(
                            source=node_id,
                            target=fw_id,
                            relationship=RelationshipType.USES_FRAMEWORK,
                            evidence={"source": "source-ast", "framework": edge_fw},
                        )
                    )
            try:
                relationship = RelationshipType(str(edge.get("relationship") or "delegated_to"))
            except ValueError:
                continue
            self.graph.add_edge(
                UnifiedEdge(
                    source=source_id,
                    target=target_id,
                    relationship=relationship,
                    evidence={
                        "source": "source-ast",
                        "framework": edge.get("framework", ""),
                        "file_path": edge.get("file_path", ""),
                        "line_number": edge.get("line_number", 0),
                        "confidence": edge.get("confidence", ""),
                        "evidence": edge.get("evidence", ""),
                        "branch": edge.get("branch", ""),
                        "branches": [edge["branch"]] if edge.get("branch") else [],
                        "kind": edge.get("kind", ""),
                        "provenance": edge.get("provenance", "declared"),
                    },
                )
            )


def _nesting_attributes(item: dict[str, Any]) -> dict[str, Any]:
    """Parent construct id and the routes the source scan could not resolve, as node attributes."""
    routes = [route for route in item.get("unresolved_routes", []) or [] if isinstance(route, dict)]
    return {
        "parent_id": str(item.get("parent_id") or ""),
        "unresolved_route_count": len(routes),
        "unresolved_route_reasons": sorted({str(route.get("reason") or "") for route in routes} - {""}),
    }


def _add_ai_stack_frameworks(graph: UnifiedGraph, ai_inventory: Any, data_source: str) -> None:
    """Project SDK/observability imports as first-class framework nodes + package/model links."""
    if not isinstance(ai_inventory, dict):
        return
    components = ai_inventory.get("components")
    if not isinstance(components, list):
        return
    projection = _AIStackProjection(graph, data_source)
    for comp in components:
        projection.project_component(comp)
    for model_name in ai_inventory.get("unique_models") or []:
        projection._ensure_model(str(model_name))
    if projection.observability_fids:
        agent_ids = [n.id for n in graph.nodes_by_type(EntityType.AGENT)]
        for fid in projection.observability_fids:
            for agent_id in agent_ids:
                graph.add_edge(
                    UnifiedEdge(
                        source=fid,
                        target=agent_id,
                        relationship=RelationshipType.OBSERVES,
                        evidence={"source": "ai-inventory"},
                    )
                )


class _AIStackProjection:
    """Per-build SDK, model and observability projection."""

    def __init__(self, graph: UnifiedGraph, data_source: str) -> None:
        self.graph = graph
        self.data_source = data_source
        self.observability_fids: list[str] = []

    def _ensure_model(self, ref: str, *, source: str = "ai-inventory") -> str | None:
        label = str(ref or "").strip()
        if not label or label.upper() == "[REDACTED]":
            return None
        mid = _model_node_id(label)
        # add_node is create-or-merge: unconditionally add so a model discovered
        # by multiple sources unions its attributes onto one node.
        self.graph.add_node(
            UnifiedNode(
                id=mid,
                entity_type=EntityType.MODEL,
                label=label,
                attributes={"model_ref": label, "source": source},
                dimensions=NodeDimensions(surface="model"),
                data_sources=[self.data_source, "ai-inventory"],
            )
        )
        return mid

    def project_component(self, comp: Any) -> None:
        if not isinstance(comp, dict):
            return
        ctype = str(comp.get("type") or "").strip().lower()
        name = str(comp.get("name") or comp.get("package") or "").strip()
        if not name:
            return

        if ctype in {"model_reference", "deprecated_model"}:
            self._ensure_model(name, source=ctype)
            return

        if ctype not in {"agent_framework", "observability"}:
            return
        kind = "observability" if ctype == "observability" else "orchestration"
        fid = stable_node_id(EntityType.FRAMEWORK.value, name.lower())
        if kind == "observability" and fid not in self.observability_fids:
            self.observability_fids.append(fid)
        if not self.graph.has_node(fid):
            self.graph.add_node(
                UnifiedNode(
                    id=fid,
                    entity_type=EntityType.FRAMEWORK,
                    label=name,
                    attributes={
                        "framework": name,
                        "framework_kind": kind,
                        "package": comp.get("package", ""),
                        "ecosystem": comp.get("ecosystem", ""),
                        "language": comp.get("language", ""),
                        "is_shadow": bool(comp.get("is_shadow")),
                        "file": comp.get("file", ""),
                        "line": comp.get("line", 0),
                    },
                    dimensions=NodeDimensions(surface=name, agent_type=kind),
                    data_sources=[self.data_source, "ai-inventory"],
                )
            )
        package_name = str(comp.get("package") or "").strip()
        ecosystem = str(comp.get("ecosystem") or "pypi").strip() or "pypi"
        if package_name:
            pkg_id = stable_node_id(EntityType.PACKAGE.value, ecosystem, package_name, "latest")
            # Prefer an existing versioned package node if present.
            existing = [
                n
                for n in self.graph.nodes_by_type(EntityType.PACKAGE)
                if str(n.attributes.get("name") or n.label).lower() == package_name.lower()
            ]
            if existing:
                pkg_id = existing[0].id
            elif not self.graph.has_node(pkg_id):
                self.graph.add_node(
                    UnifiedNode(
                        id=pkg_id,
                        entity_type=EntityType.PACKAGE,
                        label=package_name,
                        attributes={
                            "name": package_name,
                            "ecosystem": ecosystem,
                            "version": "latest",
                            "from_ai_inventory": True,
                        },
                        data_sources=[self.data_source, "ai-inventory"],
                    )
                )
            self.graph.add_edge(
                UnifiedEdge(
                    source=fid,
                    target=pkg_id,
                    relationship=RelationshipType.DEPENDS_ON,
                    evidence={"source": "ai-inventory", "framework": name},
                )
            )
