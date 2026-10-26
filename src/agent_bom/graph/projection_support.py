"""Shared report projection primitives; independent of builder orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePath
from typing import Any

from agent_bom.canonical_ids import agent_graph_id, agent_identity_scope
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import RelationshipType


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _agent_identity_scope(agent_dict: dict[str, Any]) -> str:
    """Return the endpoint/source scope that disambiguates fleet agents."""
    return agent_identity_scope(agent_dict)


def _agent_node_id(agent_name: Any, source_id: str = "") -> str:
    """Build an agent graph ID without collapsing same-name fleet endpoints."""
    return agent_graph_id(agent_name, source_id)


def _add_rel_edge(
    graph: UnifiedGraph,
    source_id: str,
    target_id: str,
    relationship: RelationshipType,
    evidence: dict[str, Any] | None = None,
    *,
    observed_at: str = "",
) -> None:
    """Add a relationship edge; thin wrapper over ``graph.add_edge(UnifiedEdge(...))``.

    ``evidence=None`` is normalized to ``{}`` to match the ``UnifiedEdge``
    default, so routed call sites stay byte-identical. ``observed_at`` is the
    record's own observation time; without it the edge takes the graph's time.
    """
    graph.add_edge(
        UnifiedEdge(
            source=source_id,
            target=target_id,
            relationship=relationship,
            evidence=evidence if evidence is not None else {},
            last_seen=observed_at,
        )
    )


def _is_sbom_import(agent: Mapping[str, Any]) -> bool:
    servers = agent.get("mcp_servers", [])
    return (
        bool(servers)
        and all(srv.get("surface") == "sbom" for srv in servers)
        and (agent.get("source") == "sbom" or str(agent.get("name") or "").startswith("sbom:"))
    )


def _is_repository_inventory(agent: Mapping[str, Any]) -> bool:
    """Recognize the explicit manifest-collector wrappers, not arbitrary agents."""
    servers = agent.get("mcp_servers", [])
    if not servers:
        return False
    if agent.get("source") == "repo-lockfiles":
        return all(srv.get("surface") == "filesystem" and not srv.get("command") for srv in servers)
    if agent.get("source") == "project":
        return all(srv.get("surface") == "other" and srv.get("command") in {"project", "github-actions"} for srv in servers)
    return False


def _repository_manifest_directory(agent: Mapping[str, Any], server: Mapping[str, Any]) -> str:
    if agent.get("source") == "repo-lockfiles":
        label = str(server.get("name") or "").removeprefix("repo-deps:")
        return "" if label == "root" else label
    args = server.get("args") or []
    root = str(agent.get("config_path") or "")
    if args and root:
        try:
            relative = str(PurePath(str(args[0])).relative_to(PurePath(root)))
            return "" if relative == "." else relative
        except ValueError:
            pass
    label = str(server.get("name") or "")
    return "" if label == str(agent.get("name") or "").removeprefix("project:") else label


def _normalized_environment(*candidates: object) -> str:
    """Return the first non-empty environment label among candidates."""
    for raw in candidates:
        if raw is None:
            continue
        text = str(raw).strip()
        if text:
            return text
    return ""
