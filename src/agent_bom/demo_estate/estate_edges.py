"""Edge helpers for the demo estate projection: evidence envelope and hop orientation."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import fixture_edge_evidence
from agent_bom.graph.types import EntityType, RelationshipType

# Stamped on every projected node/edge so a demo estate is never mistaken for a scan.
ESTATE_DATA_SOURCE = "demo-estate"


def add_estate_edge(graph: UnifiedGraph, source: str, target: str, relationship: RelationshipType, **kwargs: object) -> None:
    # Where an agent runs is execution context for the agent read, not an attack hop: the
    # path to a CVE still goes agent -> server -> workload -> image -> package.
    if relationship is RelationshipType.HOSTED_ON and graph.nodes[source].entity_type is EntityType.AGENT:
        kwargs.setdefault("traversable", False)
    evidence = fixture_edge_evidence(relationship, ESTATE_DATA_SOURCE, kwargs.pop("evidence", None))  # type: ignore[arg-type]
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, evidence=evidence, **kwargs))  # type: ignore[arg-type]


def oriented_topology_edge(
    graph: UnifiedGraph, tag: str, source: str, target: str, relationship: RelationshipType
) -> tuple[str, str, RelationshipType]:
    """Images consume their package contents; a dataset's "reads_data" is lineage the store holds.

    A container's recorded ``cluster`` is where it runs, the ``HOSTED_ON`` edge
    the live builder draws for a pod, not mere membership.
    """
    kind = graph.nodes[source].entity_type
    if tag == "container_image" and kind == EntityType.PACKAGE:
        return target, source, relationship
    if tag == "cluster" and kind == EntityType.CONTAINER and graph.nodes[target].entity_type == EntityType.CLUSTER:
        return source, target, RelationshipType.HOSTED_ON
    if tag == "reads_data" and kind == EntityType.DATASET:
        return target, source, RelationshipType.STORES
    return source, target, relationship
