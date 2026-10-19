"""Package -> package ``DEPENDS_ON`` edges from the recorded dependency tree.

Only parent -> child edges an inventory records are drawn; the transitive
closure is never materialized, so the edge count is bounded by the package
count. A parent links only when it names exactly one package in the same
ecosystem and inventory (:mod:`agent_bom.core.package_lineage`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from agent_bom.core.package_lineage import DependencyRecord, resolve_dependency_edges
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import EntityType, RelationshipType


def _record(stable_id: str, pkg: Mapping[str, Any]) -> DependencyRecord:
    evidence = pkg.get("version_evidence")
    return DependencyRecord(
        stable_id=stable_id,
        name=str(pkg.get("name") or ""),
        ecosystem=str(pkg.get("ecosystem") or ""),
        is_direct=bool(pkg.get("is_direct", True)),
        parent_package=str(pkg.get("parent_package") or "") or None,
        version_evidence=tuple(item for item in evidence if isinstance(item, Mapping)) if isinstance(evidence, list) else (),
    )


def project_package_dependencies(
    graph: UnifiedGraph,
    packages: Iterable[Mapping[str, Any]],
    *,
    node_id_for: Callable[[Any], str],
    data_source: str,
    tier: str = "static_scan",
) -> int:
    """Add one ``DEPENDS_ON`` edge per resolved parent/child pair; returns edges added."""
    node_ids: dict[str, str] = {}
    records: list[DependencyRecord] = []
    for pkg in packages:
        node_id = node_id_for(pkg)
        stable_id = str(pkg.get("stable_id") or node_id)
        node_ids[stable_id] = node_id
        records.append(_record(stable_id, pkg))
    edges, _unresolved = resolve_dependency_edges(records)
    added = 0
    for parent, child in edges:
        source, target = node_ids.get(parent, ""), node_ids.get(child, "")
        if not source or not target or source == target:
            continue
        source_node, target_node = graph.nodes.get(source), graph.nodes.get(target)
        if source_node is None or target_node is None:
            continue
        if source_node.entity_type != EntityType.PACKAGE or target_node.entity_type != EntityType.PACKAGE:
            continue
        graph.add_edge(
            UnifiedEdge(
                source=source,
                target=target,
                relationship=RelationshipType.DEPENDS_ON,
                evidence={"source": data_source, "tier": tier, "reason": "recorded_parent_package"},
            )
        )
        added += 1
    return added
