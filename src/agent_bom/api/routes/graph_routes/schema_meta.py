"""Relationship taxonomy metadata served by ``GET /v1/graph/schema``.

Derived from :mod:`agent_bom.graph.relationship_specs`, the registry the graph
enforces on write, so the published schema cannot drift from what is accepted.
``source_types`` / ``target_types`` stay for existing consumers; ``allowed_pairs``
is the exact contract (the two type lists are not a cartesian product).
"""

from __future__ import annotations

from agent_bom.graph.relationship_specs import RELATIONSHIP_SPECS, RelationshipSpec


def _meta(spec: RelationshipSpec) -> dict[str, object]:
    return {
        "category": spec.category,
        "direction": spec.direction,
        "source_types": [kind.value for kind in spec.source_types],
        "target_types": [kind.value for kind in spec.target_types],
        "traversable": spec.default_traversable,
        "traversal_class": spec.traversal_class.value,
        "required_evidence": list(spec.required_evidence),
        "allowed_pairs": sorted([source.value, target.value] for source, target in spec.allowed_pairs),
    }


_RELATIONSHIP_SCHEMA_META: dict[str, dict[str, object]] = {rel.value: _meta(spec) for rel, spec in RELATIONSHIP_SPECS.items()}
