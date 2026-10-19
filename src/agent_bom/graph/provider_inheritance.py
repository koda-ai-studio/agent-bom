"""Cloud provider inherited over recorded containment and hosting edges.

An EKS cluster declares AWS; the containers it hosts usually do not. The edge
already proves where they run, so the provider follows it. Names are never
read, findings and packages are never stamped, and any disagreement anywhere
along the chain leaves the provider unset rather than picking one.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

DECLARED = "declared"
_MAX_DEPTH = 8

_SCOPES = frozenset({EntityType.ACCOUNT, EntityType.CLUSTER, EntityType.ENVIRONMENT})
_INHERITORS = frozenset(
    {
        EntityType.ACCOUNT,
        EntityType.CLUSTER,
        EntityType.ENVIRONMENT,
        EntityType.CONTAINER,
        EntityType.CLOUD_RESOURCE,
        EntityType.RESOURCE,
        EntityType.DATA_STORE,
        EntityType.API_GATEWAY,
        EntityType.DATASET,
        EntityType.MODEL,
        EntityType.ROLE,
        EntityType.POLICY,
        EntityType.USER,
        EntityType.GROUP,
        EntityType.SERVICE_ACCOUNT,
        EntityType.SERVICE_PRINCIPAL,
        EntityType.FEDERATED_IDENTITY,
    }
)
# A workload scheduled on a VM or pod runs wherever that host runs.
_HOSTS = frozenset({EntityType.CLOUD_RESOURCE, EntityType.CONTAINER})
_PARENT_TO_CHILD = frozenset({RelationshipType.CONTAINS, RelationshipType.OWNS, RelationshipType.HOSTS})
_CHILD_TO_PARENT = frozenset({RelationshipType.HOSTED_ON, RelationshipType.PART_OF})


def declared_provider(node: UnifiedNode) -> str | None:
    """The node's own provider, ``""`` when absent, ``None`` when it conflicts."""
    values = {
        value.strip().lower()
        for value in (node.dimensions.cloud_provider, node.attributes.get("cloud_provider"))
        if isinstance(value, str) and value.strip()
    }
    if len(values) > 1:
        return None
    return next(iter(values), "")


def provider_basis(node: UnifiedNode) -> str:
    """How the node's effective provider was established, ``""`` when it has none."""
    basis = node.attributes.get("cloud_provider_basis")
    if isinstance(basis, str) and basis.startswith("inherited:"):
        return basis
    return DECLARED if declared_provider(node) else ""


def provider_fields(node: UnifiedNode) -> dict[str, str]:
    """The effective provider and its basis, for roll-up cards and breadcrumbs."""
    provider = declared_provider(node) or ""
    return {"cloud_provider": provider, "cloud_provider_basis": provider_basis(node) if provider else ""}


def _parents(graph: UnifiedGraph) -> dict[str, list[tuple[str, str]]]:
    parents: dict[str, list[tuple[str, str]]] = {}
    for edge in graph.edges:
        if edge.relationship in _PARENT_TO_CHILD:
            parent, child = edge.source, edge.target
        elif edge.relationship in _CHILD_TO_PARENT:
            parent, child = edge.target, edge.source
        else:
            continue
        source, target = graph.nodes.get(parent), graph.nodes.get(child)
        if source is None or target is None or parent == child:
            continue
        scoped = source.entity_type in _SCOPES or (edge.relationship is RelationshipType.HOSTED_ON and source.entity_type in _HOSTS)
        if scoped and target.entity_type in _INHERITORS:
            parents.setdefault(child, []).append((parent, edge.relationship.value))
    return parents


def _ancestor_providers(graph: UnifiedGraph, parents: dict[str, list[tuple[str, str]]]) -> dict[str, set[str]]:
    """Every provider declared on a node or any ancestor; ``"?"`` marks a conflict."""
    seen: dict[str, set[str]] = {}
    for node_id, node in graph.nodes.items():
        own = declared_provider(node)
        seen[node_id] = {"?"} if own is None else ({own} if own else set())
    for _ in range(_MAX_DEPTH):
        changed = False
        for child, links in parents.items():
            merged = seen[child].union(*(seen[parent] for parent, _ in links))
            if merged != seen[child]:
                seen[child], changed = merged, True
        if not changed:
            break
    return seen


def _stamp(child: UnifiedNode, provider: str, parent: UnifiedNode, relationship: str) -> None:
    child.dimensions.cloud_provider = provider
    child.attributes["cloud_provider_basis"] = f"inherited:{relationship}"
    child.attributes["cloud_provider_source"] = {
        "node_id": parent.id,
        "label": parent.label,
        "entity_type": parent.entity_type.value,
    }


def inherit_cloud_provider(graph: UnifiedGraph) -> int:
    """Stamp the one provider proven by containment onto assets without one."""
    parents = _parents(graph)
    if not parents:
        return 0
    providers = _ancestor_providers(graph, parents)
    stamped = 0
    for child_id in sorted(parents):
        child = graph.nodes[child_id]
        candidates = providers[child_id]
        if declared_provider(child) != "" or len(candidates) != 1 or "?" in candidates:
            continue
        provider = next(iter(candidates))
        links: list[tuple[str, Any]] = sorted(parents[child_id])
        parent_id, relationship = next(link for link in links if providers[link[0]] == {provider})
        _stamp(child, provider, graph.nodes[parent_id], relationship)
        stamped += 1
    return stamped
