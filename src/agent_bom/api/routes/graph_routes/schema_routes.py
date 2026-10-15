"""Graph legend and canonical schema routes (no tenant data)."""

from __future__ import annotations

from fastapi import APIRouter

from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph import GraphLegendResponse, GraphSchemaResponse
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.routes.graph_routes.params import _SEMANTIC_LAYER_LABELS
from agent_bom.api.routes.graph_routes.schema_meta import _RELATIONSHIP_SCHEMA_META
from agent_bom.graph import EntityType, GraphSemanticLayer, RelationshipType

router = APIRouter(route_class=_GraphAdmissionRoute)


@router.get("/graph/legend", **documented(GraphLegendResponse), tags=["graph"], deprecated=True)
def get_graph_legend() -> dict:
    """Return entity and relationship legends for UI rendering.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).
    """
    from agent_bom.graph import ENTITY_LEGEND, RELATIONSHIP_LEGEND

    return {
        "entities": [{"key": e.key, "label": e.label, "color": e.color, "shape": e.shape, "layer": e.layer} for e in ENTITY_LEGEND],
        "relationships": [{"key": r.key, "label": r.label, "color": r.color} for r in RELATIONSHIP_LEGEND],
    }


# Map canonical "shape" hint → icon hint that the TS lineage-nodes module
# understands.  Keeping the mapping server-side means the TypeScript codegen
# stays a thin renderer; adding a new icon in lucide just means changing the
# server map and re-running the codegen.
_SHAPE_TO_ICON: dict[str, str] = {
    "circle": "circle",
    "diamond": "diamond",
    "square": "square",
    "triangle": "triangle",
}


_RESERVED_GRAPH_NODE_KINDS: dict[str, tuple[list[str], str]] = {
    EntityType.CREDENTIAL_REF.value: ([], "Reserved vocabulary; no production emitter. Demo or legacy snapshots may contain it."),
    EntityType.CLUSTER.value: ([], "Reserved vocabulary; no production emitter. Demo or legacy snapshots may contain it."),
    EntityType.ENVIRONMENT.value: ([], "Reserved vocabulary; no production emitter. Demo or legacy snapshots may contain it."),
    EntityType.TOOL_CALL.value: ([], "Reserved vocabulary; no production emitter. Demo or legacy snapshots may contain it."),
    EntityType.EXTERNAL_IMPORT.value: (
        ["code_graph"],
        "Reserved for source-code import topology; static supply-chain scans do not emit import nodes yet.",
    ),
}


_RESERVED_GRAPH_EDGE_KINDS: dict[str, tuple[list[str], str]] = {
    RelationshipType.SHARES_CRED.value: ([], "Reserved vocabulary; no production emitter. Retained for stored snapshots."),
    RelationshipType.LATERAL_PATH.value: ([], "Reserved vocabulary; no production emitter. Retained for stored snapshots."),
    RelationshipType.INHERITS.value: ([], "Reserved vocabulary; no production emitter. Retained for stored snapshots."),
    RelationshipType.IMPORTS.value: (
        ["code_graph"],
        "Reserved for source-code topology linking files, modules, packages, and imports.",
    ),
    RelationshipType.REMEDIATES.value: (
        ["remediation_graph"],
        "Reserved for fixed-version and remediation-plan graph edges.",
    ),
    RelationshipType.ACTED_AS.value: (
        ["runtime_graph"],
        "Reserved for explicit user/service-principal runtime delegation once traces carry that identity link.",
    ),
}


def _graph_schema_emission_meta(
    key: str,
    *,
    reserved: dict[str, tuple[list[str], str]],
    emitted_surfaces: dict[str, list[str]],
) -> dict[str, object]:
    """Document whether a graph kind is emitted today or reserved vocabulary."""
    if key in emitted_surfaces:
        return {
            "emission_status": "emitted",
            "emission_surfaces": emitted_surfaces[key],
            "emission_notes": "Emitted by at least one graph builder or runtime projection.",
        }
    if key in reserved:
        surfaces, notes = reserved[key]
        return {
            "emission_status": "reserved",
            "emission_surfaces": surfaces,
            "emission_notes": notes,
        }
    return {
        "emission_status": "reserved",
        "emission_surfaces": [],
        "emission_notes": "Reserved vocabulary; no verified production emitter. Demo or legacy snapshots may contain this kind.",
    }


@router.get("/graph/schema", **documented(GraphSchemaResponse), tags=["graph"])
def get_graph_schema() -> dict:
    """Canonical graph entity/edge taxonomy — single source of truth.

    Drives the TypeScript codegen at ``ui/scripts/codegen-graph-schema.mjs``,
    which materialises ``ui/lib/graph-schema.generated.ts``.  CI fails the
    build when the checked-in generated file drifts from what this endpoint
    would emit, so adding a new ``EntityType`` or ``RelationshipType`` in
    Python automatically forces a regen + commit on the UI side.
    """
    from agent_bom.graph import ENTITY_LEGEND, ENTITY_OCSF_MAP, RELATIONSHIP_LEGEND
    from agent_bom.graph.emitter_scan import production_emitters
    from agent_bom.graph.integration_contract import GRAPH_COMPATIBILITY
    from agent_bom.graph.types import EntityType, RelationshipType

    legend_entities = {entry.key: entry for entry in ENTITY_LEGEND}
    legend_relationships = {entry.key: entry for entry in RELATIONSHIP_LEGEND}

    node_kinds = []
    for entity in EntityType:
        legend = legend_entities.get(entity.value)
        label = legend.label if legend else entity.value.replace("_", " ").title()
        color = legend.color if legend else "#6b7280"
        shape = legend.shape if legend else "circle"
        layer = legend.layer if legend and legend.layer else GraphSemanticLayer.ASSET.value
        node_kinds.append(
            {
                "key": entity.value,
                "label": label,
                "color": color,
                "shape": shape,
                "layer": layer,
                "icon": _SHAPE_TO_ICON.get(shape, "circle"),
                "category_uid": ENTITY_OCSF_MAP.get(entity.value, {}).get("category_uid", 0),
                "class_uid": ENTITY_OCSF_MAP.get(entity.value, {}).get("class_uid", 0),
                **_graph_schema_emission_meta(
                    entity.value,
                    reserved=_RESERVED_GRAPH_NODE_KINDS,
                    emitted_surfaces=production_emitters(relationships=False),
                ),
            }
        )

    edge_kinds = []
    for rel in RelationshipType:
        legend = legend_relationships.get(rel.value)
        label = legend.label if legend else rel.value.replace("_", " ").title()
        color = legend.color if legend else "#6b7280"
        edge_kinds.append(
            {
                "key": rel.value,
                "label": label,
                "color": color,
                **_graph_schema_emission_meta(
                    rel.value,
                    reserved=_RESERVED_GRAPH_EDGE_KINDS,
                    emitted_surfaces=production_emitters(relationships=True),
                ),
                **_RELATIONSHIP_SCHEMA_META.get(
                    rel.value,
                    {
                        "category": "custom",
                        "direction": "directed",
                        "source_types": [],
                        "target_types": [],
                        "traversable": True,
                    },
                ),
            }
        )

    return {
        "version": 1,
        "interchange": GRAPH_COMPATIBILITY,
        "semantic_layers": [{"key": layer.value, "label": _SEMANTIC_LAYER_LABELS[layer.value]} for layer in GraphSemanticLayer],
        "node_kinds": sorted(node_kinds, key=lambda d: d["key"]),
        "edge_kinds": sorted(edge_kinds, key=lambda d: d["key"]),
        "node_types": sorted(entity.value for entity in EntityType),
        "edge_types": sorted(rel.value for rel in RelationshipType),
    }
