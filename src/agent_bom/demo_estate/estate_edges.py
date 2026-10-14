"""Edge helpers for the demo estate projection: evidence envelope and hop orientation."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import fixture_edge_evidence
from agent_bom.graph.types import EntityType, RelationshipType

# Stamped on every projected node/edge so a demo estate is never mistaken for a scan.
ESTATE_DATA_SOURCE = "demo-estate"


def add_estate_edge(graph: UnifiedGraph, source: str, target: str, relationship: RelationshipType, **kwargs: object) -> None:
    evidence = fixture_edge_evidence(relationship, ESTATE_DATA_SOURCE, kwargs.pop("evidence", None))  # type: ignore[arg-type]
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, evidence=evidence, **kwargs))  # type: ignore[arg-type]


def oriented_topology_edge(
    graph: UnifiedGraph, tag: str, source: str, target: str, relationship: RelationshipType
) -> tuple[str, str, RelationshipType]:
    """Images consume their package contents; a dataset's "reads_data" is lineage the store holds."""
    kind = graph.nodes[source].entity_type
    if tag == "container_image" and kind == EntityType.PACKAGE:
        return target, source, relationship
    if tag == "reads_data" and kind == EntityType.DATASET:
        return target, source, RelationshipType.STORES
    return source, target, relationship
