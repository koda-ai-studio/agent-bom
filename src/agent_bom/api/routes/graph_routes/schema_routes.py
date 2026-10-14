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


# Production emitter modules, verified against the generated entity/relationship
# catalogs. Compatibility adapters and demo fixtures are not production emitters.
_EMITTED_GRAPH_NODE_SURFACES: dict[str, list[str]] = {
    "agent": [
        "graph/agent_projection.py",
        "graph/builder_overlays.py",
        "graph/builder_snowflake_governance.py",
        "graph/framework_topology_projection.py",
        "graph/governance_overlay.py",
        "graph/runtime_projection.py",
        "graph/trace_projection.py",
    ],
    "server": ["graph/agent_projection.py", "graph/trace_projection.py"],
    "package": ["graph/agent_projection.py", "graph/framework_topology_projection.py"],
    "tool": [
        "graph/agent_projection.py",
        "graph/ast_tool_projection.py",
        "graph/governance_overlay.py",
        "graph/runtime_projection.py",
        "graph/trace_projection.py",
    ],
    "model": ["graph/finding_row_projection.py", "graph/framework_topology_projection.py", "graph/training_projection.py"],
    "dataset": ["graph/training_projection.py"],
    "framework": ["graph/framework_topology_projection.py"],
    "container": ["graph/finding_row_projection.py", "graph/training_projection.py"],
    "cloud_resource": [
        "graph/benchmark_projection.py",
        "graph/builder.py",
        "graph/builder_cloud_lineage.py",
        "graph/builder_network_inventory.py",
        "graph/builder_snowflake_data_movement.py",
        "graph/builder_snowflake_platform.py",
        "graph/cloud_compute_projection.py",
        "graph/cloud_rbac.py",
        "graph/cloud_service_projection.py",
        "graph/cloud_storage_projection.py",
        "graph/finding_projection.py",
    ],
    "resource": ["graph/builder_cloud_principals.py", "hardware_evidence.py"],
    "source_file": ["graph/agent_projection.py", "graph/ast_tool_projection.py", "graph/repo_structure_overlay.py"],
    "code_module": ["graph/ast_tool_projection.py", "graph/code_graph_overlay.py"],
    "config_file": ["graph/finding_row_projection.py", "graph/repo_structure_overlay.py"],
    "ci_job": ["graph/ci_graph_overlay.py"],
    "directory": ["graph/agent_projection.py", "graph/repo_structure_overlay.py"],
    "vulnerability": [
        "graph/blast_projection.py",
        "graph/builder_overlays.py",
        "graph/finding_row_projection.py",
        "graph/package_projection.py",
        "hardware_evidence.py",
    ],
    "misconfiguration": [
        "graph/benchmark_projection.py",
        "graph/builder.py",
        "graph/finding_projection.py",
        "graph/finding_row_projection.py",
        "graph/mcp_audit_projection.py",
    ],
    "credential": ["graph/credential_projection.py"],
    "org": [
        "graph/builder.py",
        "graph/builder_cloud_inventory.py",
        "graph/builder_cloud_lineage.py",
        "graph/builder_snowflake_platform.py",
    ],
    "account": [
        "graph/benchmark_projection.py",
        "graph/builder.py",
        "graph/builder_cloud_inventory.py",
        "graph/builder_cloud_lineage.py",
        "graph/builder_snowflake_data_movement.py",
        "graph/builder_snowflake_governance.py",
        "graph/builder_snowflake_lane.py",
        "graph/builder_snowflake_objects.py",
        "graph/builder_snowflake_platform.py",
        "graph/cloud_context.py",
        "graph/cloud_rbac.py",
    ],
    "user": [
        "graph/authorization_evidence.py",
        "graph/builder.py",
        "graph/builder_snowflake_governance.py",
        "graph/builder_snowflake_objects.py",
        "graph/cloud_context.py",
        "graph/cloud_rbac.py",
    ],
    "group": ["graph/authorization_evidence.py", "graph/builder.py", "graph/cloud_context.py", "graph/cloud_rbac.py"],
    "role": [
        "graph/builder_cloud_inventory.py",
        "graph/builder_snowflake_objects.py",
        "graph/builder_snowflake_platform.py",
        "graph/cloud_context.py",
        "graph/finding_row_projection.py",
    ],
    "policy": ["graph/builder.py", "graph/builder_cloud_lineage.py", "graph/cloud_context.py"],
    "service_account": ["graph/authorization_evidence.py", "graph/builder.py", "graph/cloud_context.py"],
    "service_principal": ["graph/authorization_evidence.py", "graph/cloud_context.py", "graph/cloud_rbac.py"],
    "federated_identity": ["graph/authorization_evidence.py", "graph/cloud_context.py"],
    "managed_identity": [
        "graph/authorization_evidence.py",
        "graph/cloud_compute_projection.py",
        "graph/cloud_context.py",
        "graph/cloud_rbac.py",
        "graph/credential_projection.py",
        "graph/governance_overlay.py",
        "graph/identity_nodes.py",
        "graph/nhi_overlay.py",
    ],
    "access_grant": ["graph/governance_overlay.py"],
    "access_policy": ["graph/governance_overlay.py"],
    "blueprint": ["graph/governance_overlay.py"],
    "drift_incident": ["graph/governance_overlay.py"],
    "data_store": [
        "graph/builder_snowflake_data_movement.py",
        "graph/builder_snowflake_governance.py",
        "graph/builder_snowflake_lane.py",
        "graph/builder_snowflake_objects.py",
        "graph/builder_snowflake_platform.py",
        "graph/cloud_service_projection.py",
        "graph/cnapp_overlay.py",
    ],
    "api_gateway": ["graph/builder_network_inventory.py"],
    "application": ["graph/aspm_overlay.py", "graph/repo_trust_overlay.py"],
    "provider": ["graph/agent_projection.py", "graph/builder.py", "graph/builder_cloud_lineage.py"],
    "fleet": ["graph/endpoint_overlay.py"],
}

_EMITTED_GRAPH_EDGE_SURFACES: dict[str, list[str]] = {
    "hosts": ["graph/agent_projection.py", "graph/builder_cloud_lineage.py"],
    "uses": ["graph/agent_projection.py"],
    "uses_framework": ["graph/framework_topology_projection.py"],
    "depends_on": [
        "graph/agent_projection.py",
        "graph/builder_snowflake_data_movement.py",
        "graph/builder_snowflake_objects.py",
        "graph/builder_snowflake_platform.py",
        "graph/framework_topology_projection.py",
        "graph/repo_structure_overlay.py",
    ],
    "provides_tool": ["graph/agent_projection.py"],
    "exposes_cred": ["graph/credential_projection.py"],
    "reaches_tool": ["graph/credential_projection.py"],
    "serves_model": ["graph/framework_topology_projection.py", "graph/training_projection.py"],
    "contains": [
        "graph/agent_projection.py",
        "graph/builder.py",
        "graph/builder_cloud_inventory.py",
        "graph/builder_cloud_lineage.py",
        "graph/builder_snowflake_platform.py",
        "graph/cloud_context.py",
        "graph/code_graph_overlay.py",
        "graph/repo_structure_overlay.py",
    ],
    "defines": ["graph/ast_tool_projection.py", "graph/code_graph_overlay.py"],
    "runs": ["graph/ci_graph_overlay.py"],
    "configures": ["graph/ci_graph_overlay.py"],
    "observes": ["graph/framework_topology_projection.py"],
    "affects": [
        "graph/benchmark_projection.py",
        "graph/builder.py",
        "graph/finding_projection.py",
        "graph/repo_structure_overlay.py",
        "hardware_evidence.py",
    ],
    "vulnerable_to": ["graph/blast_projection.py", "graph/mcp_audit_projection.py", "graph/package_projection.py"],
    "exploitable_via": ["graph/package_projection.py"],
    "triggers": ["graph/finding_projection.py"],
    "shares_server": ["graph/blast_projection.py"],
    "manages": ["graph/builder_cloud_lineage.py"],
    "owns": ["graph/builder.py", "graph/builder_snowflake_governance.py", "graph/cloud_context.py"],
    "part_of": [
        "graph/builder_cloud_lineage.py",
        "graph/builder_network_inventory.py",
        "graph/cloud_compute_projection.py",
        "hardware_evidence.py",
    ],
    "member_of": ["graph/builder.py", "graph/builder_cloud_lineage.py", "graph/builder_snowflake_objects.py"],
    "assumes": [
        "graph/builder_cloud_inventory.py",
        "graph/builder_snowflake_objects.py",
        "graph/builder_snowflake_platform.py",
        "graph/cloud_compute_projection.py",
    ],
    "trusts": ["graph/builder.py", "graph/builder_cloud_lineage.py"],
    "attached": ["graph/builder.py", "graph/builder_cloud_lineage.py", "graph/governance_overlay.py"],
    "can_access": ["graph/authorization_evidence.py", "graph/builder.py", "graph/builder_cloud_lineage.py"],
    "cross_account_trust": ["graph/builder.py", "graph/builder_cloud_lineage.py"],
    "authenticates_as": ["graph/credential_projection.py", "graph/governance_overlay.py"],
    "scoped_to": ["graph/governance_overlay.py", "graph/nhi_overlay.py"],
    "governs": ["graph/builder.py", "graph/governance_overlay.py"],
    "exhibits_drift": ["graph/governance_overlay.py"],
    "exposed_to": [
        "graph/builder.py",
        "graph/builder_network_exposure.py",
        "graph/builder_snowflake_data_movement.py",
        "graph/cloud_compute_projection.py",
        "graph/cnapp_overlay.py",
    ],
    "stores": ["graph/cnapp_overlay.py"],
    "has_permission": [
        "graph/builder.py",
        "graph/builder_cloud_principals.py",
        "graph/builder_snowflake_objects.py",
        "graph/cloud_rbac.py",
        "graph/effective_permissions.py",
    ],
    "protects": ["graph/builder_network_inventory.py"],
    "invoked": ["graph/builder.py", "graph/runtime_projection.py", "graph/trace_projection.py"],
    "called": ["graph/runtime_projection.py", "graph/trace_projection.py"],
    "used_credential": ["graph/runtime_projection.py", "graph/trace_projection.py"],
    "accessed": ["graph/builder.py", "graph/builder_snowflake_governance.py", "graph/runtime_projection.py", "graph/trace_projection.py"],
    "delegated_to": ["graph/runtime_projection.py"],
    "correlates_with": ["graph/builder_frameworks.py"],
    "possibly_correlates_with": ["graph/builder_frameworks.py"],
    "belongs_to": ["graph/aspm_overlay.py"],
}


def _graph_schema_emission_meta(
    key: str,
    *,
    reserved: dict[str, tuple[list[str], str]],
    emitted_surfaces: dict[str, list[str]],
) -> dict[str, object]:
    """Document whether a graph kind is emitted today or reserved vocabulary."""
    if key in reserved:
        surfaces, notes = reserved[key]
        return {
            "emission_status": "reserved",
            "emission_surfaces": surfaces,
            "emission_notes": notes,
        }
    if key not in emitted_surfaces:
        return {
            "emission_status": "reserved",
            "emission_surfaces": [],
            "emission_notes": "Reserved vocabulary; no verified production emitter. Demo or legacy snapshots may contain this kind.",
        }
    return {
        "emission_status": "emitted",
        "emission_surfaces": emitted_surfaces[key],
        "emission_notes": "Emitted by at least one graph builder or runtime projection.",
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
                    emitted_surfaces=_EMITTED_GRAPH_NODE_SURFACES,
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
                    emitted_surfaces=_EMITTED_GRAPH_EDGE_SURFACES,
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
