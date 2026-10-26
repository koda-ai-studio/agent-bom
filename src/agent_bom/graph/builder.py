"""Unified graph builder from serialized AIBOM report data.

This ingests the JSON contract emitted by ``output.json_fmt.to_json()``
and builds the core inventory, finding, runtime, and compliance entities
used for current-state views, traversal, attack paths, and temporal diffs.
"""

from __future__ import annotations

import hashlib as hashlib
import json as json
import logging
from collections.abc import Mapping
from typing import Any

from agent_bom.api.tracing import get_tracer
from agent_bom.cloud.normalization import coerce_truthy as coerce_truthy
from agent_bom.core.cloud_identity import cloud_resource_node_id as cloud_resource_node_id
from agent_bom.graph.activity_projection import project_recorded_activity
from agent_bom.graph.agent_cloud_lineage import _add_agent_cloud_lineage as _add_agent_cloud_lineage
from agent_bom.graph.agent_projection import project_agents
from agent_bom.graph.asset_canonicalize import canonicalize_assets
from agent_bom.graph.ast_tool_projection import _apply_ast_tool_overlay as _apply_ast_tool_overlay
from agent_bom.graph.ast_tool_projection import _project_ast_entrypoints as _project_ast_entrypoints
from agent_bom.graph.ast_tool_projection import _project_ast_tools as _project_ast_tools
from agent_bom.graph.authorization_evidence import apply_authorization_evidence, has_authoritative_authorization_evidence
from agent_bom.graph.benchmark_projection import benchmark_inputs, project_benchmarks
from agent_bom.graph.blast_projection import enrich_blast_radius, project_blast_radius, project_package_exploits, project_shared_servers
from agent_bom.graph.build_analysis import GraphAnalysisPorts, apply_build_analysis
from agent_bom.graph.build_indexes import BuildIndexes
from agent_bom.graph.build_input import GraphBuildInput
from agent_bom.graph.builder_cloud_inventory import _add_management_group_hierarchy, _wire_instance_profile_roles
from agent_bom.graph.builder_cloud_lineage import _add_cloud_principal_lineage as _add_cloud_principal_lineage
from agent_bom.graph.builder_cloud_lineage import _add_lineage_resource_nodes as _add_lineage_resource_nodes
from agent_bom.graph.builder_cloud_lineage import _add_lineage_scope_edges as _add_lineage_scope_edges
from agent_bom.graph.builder_cloud_lineage import _resolve_cloud_lineage as _resolve_cloud_lineage
from agent_bom.graph.builder_cloud_principals import _add_access_advisor_grants
from agent_bom.graph.builder_cloud_principals import (
    _role_last_used_at as _role_last_used_at,
)
from agent_bom.graph.builder_frameworks import _add_cross_env_correlation, _project_host_agent_id
from agent_bom.graph.builder_network_edges import (
    _GCP_LB_COLLECTION as _GCP_LB_COLLECTION,
)
from agent_bom.graph.builder_network_edges import (
    _NETWORK_EDGE_COLLECTIONS as _NETWORK_EDGE_COLLECTIONS,
)
from agent_bom.graph.builder_network_exposure import (
    _add_exposure_path_edge as _add_exposure_path_edge,
)
from agent_bom.graph.builder_network_exposure import _apply_gcp_firewall_exposure, _link_internet_facing_load_balancers
from agent_bom.graph.builder_network_exposure import (
    _gcp_firewall_applies as _gcp_firewall_applies,
)
from agent_bom.graph.builder_network_exposure import (
    _instance_internet_reachable as _instance_internet_reachable,
)
from agent_bom.graph.builder_network_inventory import NETWORK_INVENTORY_STAGES as NETWORK_INVENTORY_STAGES
from agent_bom.graph.builder_network_inventory import _NetworkInventoryContext as _NetworkInventoryContext
from agent_bom.graph.builder_overlays import (
    _apply_agent_reach_risk as _apply_agent_reach_risk,
)
from agent_bom.graph.builder_overlays import (
    _apply_aspm_overlay as _apply_aspm_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_ci_graph_overlay as _apply_ci_graph_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_code_graph_overlay as _apply_code_graph_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_cost_overlay as _apply_cost_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_repo_structure_overlay as _apply_repo_structure_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_repo_trust_overlay as _apply_repo_trust_overlay,
)
from agent_bom.graph.builder_overlays import (
    _apply_runtime_evidence_overlay as _apply_runtime_evidence_overlay,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _EXFIL_STAGE_SERVICE as _EXFIL_STAGE_SERVICE,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _SF_EXTERNAL_BUCKET_SERVICE as _SF_EXTERNAL_BUCKET_SERVICE,
)
from agent_bom.graph.builder_snowflake_data_movement import _add_snowflake_exfil as _add_snowflake_exfil
from agent_bom.graph.builder_snowflake_data_movement import _add_snowflake_external_data as _add_snowflake_external_data
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_external_stages as _add_snowflake_external_stages,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_external_tables as _add_snowflake_external_tables,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_iceberg_tables as _add_snowflake_iceberg_tables,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_outbound_shares as _add_snowflake_outbound_shares,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_sensitive_objects as _add_snowflake_sensitive_objects,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _add_snowflake_stage_bucket as _add_snowflake_stage_bucket,
)
from agent_bom.graph.builder_snowflake_data_movement import (
    _link_iceberg_bucket as _link_iceberg_bucket,
)
from agent_bom.graph.builder_snowflake_governance import (
    _add_cortex_agent_nodes as _add_cortex_agent_nodes,
)
from agent_bom.graph.builder_snowflake_governance import (
    _add_snowflake_access_edges as _add_snowflake_access_edges,
)
from agent_bom.graph.builder_snowflake_governance import _add_snowflake_activity as _add_snowflake_activity
from agent_bom.graph.builder_snowflake_governance import _add_snowflake_governance as _add_snowflake_governance
from agent_bom.graph.builder_snowflake_governance import (
    _aggregate_cortex_agent_usage as _aggregate_cortex_agent_usage,
)
from agent_bom.graph.builder_snowflake_governance import (
    _collect_snowflake_access as _collect_snowflake_access,
)
from agent_bom.graph.builder_snowflake_governance import (
    _snowflake_access_receipt as _snowflake_access_receipt,
)
from agent_bom.graph.builder_snowflake_lane import _needs_account_scope as _needs_account_scope
from agent_bom.graph.builder_snowflake_lane import (
    _snowflake_data_store as _snowflake_data_store,
)
from agent_bom.graph.builder_snowflake_lane import (
    _snowflake_thin_node as _snowflake_thin_node,
)
from agent_bom.graph.builder_snowflake_lane import (
    _SnowflakeLane as _SnowflakeLane,
)
from agent_bom.graph.builder_snowflake_objects import (
    _add_snowflake_auth_posture as _add_snowflake_auth_posture,
)
from agent_bom.graph.builder_snowflake_objects import _add_snowflake_identity as _add_snowflake_identity
from agent_bom.graph.builder_snowflake_objects import (
    _add_snowflake_login_threats as _add_snowflake_login_threats,
)
from agent_bom.graph.builder_snowflake_objects import _add_snowflake_object_graph as _add_snowflake_object_graph
from agent_bom.graph.builder_snowflake_objects import (
    _enrich_snowflake_user as _enrich_snowflake_user,
)
from agent_bom.graph.builder_snowflake_objects import (
    _SnowflakeObjectGraph as _SnowflakeObjectGraph,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_databases as _add_snowflake_databases,
)
from agent_bom.graph.builder_snowflake_platform import _add_snowflake_integrations as _add_snowflake_integrations
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_organization as _add_snowflake_organization,
)
from agent_bom.graph.builder_snowflake_platform import _add_snowflake_pipeline as _add_snowflake_pipeline
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_pipes as _add_snowflake_pipes,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_schemas as _add_snowflake_schemas,
)
from agent_bom.graph.builder_snowflake_platform import _add_snowflake_services as _add_snowflake_services
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_streams as _add_snowflake_streams,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_tasks as _add_snowflake_tasks,
)
from agent_bom.graph.builder_snowflake_platform import (
    _add_snowflake_warehouses as _add_snowflake_warehouses,
)
from agent_bom.graph.builder_snowflake_platform import (
    _link_snowflake_objects_to_schemas as _link_snowflake_objects_to_schemas,
)
from agent_bom.graph.cloud_audit_projection import add_cloud_audit_behavioral as _add_cloud_audit_behavioral
from agent_bom.graph.cloud_compute_projection import project_instances, project_security_groups
from agent_bom.graph.cloud_context import _add_account_resource_hierarchy as _add_account_resource_hierarchy
from agent_bom.graph.cloud_context import (
    _add_identity_node,
    _identity_entity_type,
    _iter_cloud_inventories,
    _policy_document_attrs,
    _trust_entries,
    cloud_inventory_sources,
)
from agent_bom.graph.cloud_context import _environment_from_tags as _environment_from_tags
from agent_bom.graph.cloud_context import (
    _normalize_azure_inventory as _normalize_azure_inventory,
)
from agent_bom.graph.cloud_context import (
    _normalize_cloud_inventory as _normalize_cloud_inventory,
)
from agent_bom.graph.cloud_context import (
    _normalize_gcp_inventory as _normalize_gcp_inventory,
)
from agent_bom.graph.cloud_context import (
    _policy_entries as _policy_entries,
)
from agent_bom.graph.cloud_context import _prepare_cloud_payload as _prepare_cloud_payload
from agent_bom.graph.cloud_context import _recorded_exposure_attributes as _recorded_exposure_attributes
from agent_bom.graph.cloud_context import _resource_environment as _resource_environment
from agent_bom.graph.cloud_context import (
    _stamp_owning_account as _stamp_owning_account,
)
from agent_bom.graph.cloud_rbac import add_cloud_role_assignments as _add_cloud_role_assignments
from agent_bom.graph.cloud_service_projection import project_aws_services, project_gcp_services
from agent_bom.graph.cloud_storage_projection import project_buckets, project_databases, project_side_scan_targets
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.credential_bindings import project_credential_bindings
from agent_bom.graph.declared_assets import declared_assets_by_identifier
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence as edge_evidence
from agent_bom.graph.finding_projection import _resolve_skill_audit_target_ids as _resolve_skill_audit_target_ids
from agent_bom.graph.finding_projection import (
    project_iac,
    project_sast,
    project_scan_findings,
    project_skill_audit,
    project_toxic_combinations,
)
from agent_bom.graph.framework_topology_projection import _add_ai_stack_frameworks as _add_ai_stack_frameworks
from agent_bom.graph.framework_topology_projection import _add_framework_topology as _add_framework_topology
from agent_bom.graph.framework_topology_projection import _AIStackProjection as _AIStackProjection
from agent_bom.graph.framework_topology_projection import _FrameworkTopology as _FrameworkTopology
from agent_bom.graph.gpu_projection import project_gpu_compute
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.network_entry_projection import _add_network_edge_inventory as _add_network_edge_inventory
from agent_bom.graph.network_entry_projection import _wire_network_entry_exposure_paths as _wire_network_entry_exposure_paths
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.normalized_resource_projection import _add_normalized_cloud_resources as _add_normalized_cloud_resources
from agent_bom.graph.organization_aws import _add_aws_organization as _add_aws_organization
from agent_bom.graph.organization_findings import _add_cloud_org_architecture_findings as _add_cloud_org_architecture_findings
from agent_bom.graph.organization_gcp import _add_gcp_organization as _add_gcp_organization
from agent_bom.graph.package_projection import (
    _add_exploitable_via_edges as _add_exploitable_via_edges,
)
from agent_bom.graph.package_projection import (
    _add_vuln_node as _add_vuln_node,
)
from agent_bom.graph.package_projection import (
    _blast_radius_package_evidence as _blast_radius_package_evidence,
)
from agent_bom.graph.package_projection import (
    _collect_compliance_tags as _collect_compliance_tags,
)
from agent_bom.graph.package_projection import (
    _has_mappable_package_version as _has_mappable_package_version,
)
from agent_bom.graph.package_projection import (
    _normalize_server_name as _normalize_server_name,
)
from agent_bom.graph.package_projection import (
    _normalize_tool_capability as _normalize_tool_capability,
)
from agent_bom.graph.package_projection import (
    _package_evidence as _package_evidence,
)
from agent_bom.graph.package_projection import (
    _package_graph_key as _package_graph_key,
)
from agent_bom.graph.package_projection import (
    _package_node_id as _package_node_id,
)
from agent_bom.graph.package_projection import (
    _package_node_id_from_parts as _package_node_id_from_parts,
)
from agent_bom.graph.package_projection import (
    _package_version_provenance_from_dict as _package_version_provenance_from_dict,
)
from agent_bom.graph.package_projection import (
    _resolve_affected_package_ids as _resolve_affected_package_ids,
)
from agent_bom.graph.package_projection import (
    _resolve_affected_server_ids as _resolve_affected_server_ids,
)
from agent_bom.graph.package_projection import (
    _tool_capabilities as _tool_capabilities,
)
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.projection_support import (
    _agent_identity_scope as _agent_identity_scope,
)
from agent_bom.graph.projection_support import (
    _agent_node_id as _agent_node_id,
)
from agent_bom.graph.projection_support import _is_repository_inventory as _is_repository_inventory
from agent_bom.graph.projection_support import _is_sbom_import as _is_sbom_import
from agent_bom.graph.projection_support import (
    _mapping_list as _mapping_list,
)
from agent_bom.graph.projection_support import _normalized_environment as _normalized_environment
from agent_bom.graph.projection_support import _repository_manifest_directory as _repository_manifest_directory
from agent_bom.graph.resource_aliases import (
    _build_cloud_resource_alias_index as _build_cloud_resource_alias_index,
)
from agent_bom.graph.resource_aliases import (
    _CloudResourceAliasIndex as _CloudResourceAliasIndex,
)
from agent_bom.graph.resource_aliases import (
    _resolve_cloud_resource_node_id as _resolve_cloud_resource_node_id,
)
from agent_bom.graph.resource_aliases import (
    _resource_tail as _resource_tail,
)
from agent_bom.graph.runtime_projection import (
    _add_agentic_identity_graph_projections as _add_agentic_identity_graph_projections,
)
from agent_bom.graph.runtime_projection import _add_runtime_incident_feedback, project_runtime_session
from agent_bom.graph.runtime_projection import (
    _iter_agentic_identity_graph_projections as _iter_agentic_identity_graph_projections,
)
from agent_bom.graph.runtime_projection import (
    _iter_runtime_incident_records as _iter_runtime_incident_records,
)
from agent_bom.graph.runtime_projection import (
    _project_agent_feedback as _project_agent_feedback,
)
from agent_bom.graph.runtime_projection import (
    _resolve_feedback_agent_ids as _resolve_feedback_agent_ids,
)
from agent_bom.graph.runtime_projection import (
    _runtime_identity_entity_type as _runtime_identity_entity_type,
)
from agent_bom.graph.runtime_projection import (
    _runtime_identity_evidence as _runtime_identity_evidence,
)
from agent_bom.graph.runtime_projection import (
    _runtime_identity_node_attributes as _runtime_identity_node_attributes,
)
from agent_bom.graph.runtime_projection import (
    _runtime_identity_relationship as _runtime_identity_relationship,
)
from agent_bom.graph.snowflake_source_lanes import _add_snowflake_source_lanes as _add_snowflake_source_lanes
from agent_bom.graph.snowflake_source_lanes import _project_snowflake_lanes as _project_snowflake_lanes
from agent_bom.graph.supabase_projection import project_supabase_inventory
from agent_bom.graph.trace_projection import project_report_trace_events
from agent_bom.graph.training_projection import (
    _flatten_compliance_tags as _flatten_compliance_tags,
)
from agent_bom.graph.training_projection import (
    _normalize_model_ref as _normalize_model_ref,
)
from agent_bom.graph.training_projection import (
    _resolve_model_id as _resolve_model_id,
)
from agent_bom.graph.training_projection import project_dataset_cards, project_model_provenance, project_serving_configs
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part
from agent_bom.graph.vercel_projection import project_vercel_inventory
from agent_bom.security import sanitize_text as sanitize_text

_GRAPH_TRACER = get_tracer("agent_bom.graph")
_logger = logging.getLogger(__name__)


def build_unified_graph_from_report(
    report_json: dict[str, Any],
    *,
    scan_id: str = "",
    tenant_id: str = "",
    container: UnifiedGraph | None = None,
) -> UnifiedGraph:
    """Adapt the serialized report to graph evidence; the caller owns container lifetime."""
    return build_unified_graph(GraphBuildInput.from_report(report_json), scan_id=scan_id, tenant_id=tenant_id, container=container)


def build_unified_graph(
    inputs: GraphBuildInput,
    *,
    scan_id: str = "",
    tenant_id: str = "",
    container: UnifiedGraph | None = None,
) -> UnifiedGraph:
    """Project inventory, findings and topology before running final graph analysis.

    A supplied store-backed container retains the same stage order and bounded
    workspace behavior as the in-memory path. This function never closes it.
    """
    span = _GRAPH_TRACER.start_span("graph.build_unified_graph_from_report") if _GRAPH_TRACER else None
    sid = scan_id or inputs.scan_id
    graph = container if container is not None else UnifiedGraph(scan_id=sid, tenant_id=tenant_id)
    indexes = project_agents(graph, inputs.agents, inputs.data_source, _add_agent_cloud_lineage)
    project_package_exploits(graph, indexes, inputs.data_source)
    project_blast_radius(graph, inputs.blast_radius, indexes, inputs.data_source)
    project_shared_servers(graph, indexes)
    report = inputs.report_sections()
    inventories = _project_inventory_findings(graph, inputs, indexes, report)
    _project_runtime_topology(graph, inputs, indexes, report, tenant_id)
    project_toxic_combinations(graph, report.get("toxic_combinations"))
    enrich_blast_radius(graph, inputs.blast_radius)
    _project_cloud_authority(graph, inventories, report, inputs.data_source)
    project_credential_bindings(graph, inputs.agents, inputs.data_source)
    canonicalize_assets(graph)
    apply_build_analysis(graph, report, _analysis_ports())
    if span is not None:
        span.set_attribute("agent_bom.graph.scan_id", sid)
        span.set_attribute("agent_bom.graph.tenant_id", tenant_id or "default")
        span.set_attribute("agent_bom.graph.agent_count", len(inputs.agents))
        span.set_attribute("agent_bom.graph.blast_radius_count", len(inputs.blast_radius))
        span.set_attribute("agent_bom.graph.node_count", len(graph.nodes))
        span.set_attribute("agent_bom.graph.edge_count", len(graph.edges))
        span.end()
    return graph


def _project_inventory_findings(
    graph: UnifiedGraph,
    inputs: GraphBuildInput,
    indexes: BuildIndexes,
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    project_model_provenance(graph, report.get("model_provenance", []))
    project_dataset_cards(graph, report.get("dataset_cards"))
    project_serving_configs(graph, report.get("serving_configs", []))
    # Native cloud assets precede benchmark references to avoid duplicate nodes.
    inventories = list(_iter_cloud_inventories(report.get("cloud_inventory")))
    for inventory in inventories:
        if native_projector := {"supabase": project_supabase_inventory, "vercel": project_vercel_inventory}.get(
            str(inventory.get("provider", ""))
        ):
            native_projector(graph, inventory)
        else:
            _add_cloud_inventory(graph, inventory, inputs.data_source)
    project_benchmarks(graph, benchmark_inputs(report), declared_assets_by_identifier(report.get("findings")))
    project_sast(graph, report.get("sast") or report.get("sast_data"))
    project_iac(graph, report.get("iac_findings") or report.get("iac_findings_data"))
    project_skill_audit(graph, report.get("skill_audit"), indexes, report.get("findings"))
    project_scan_findings(graph, report.get("findings"))
    project_gpu_compute(graph, report, indexes, inputs.data_source)
    return inventories


def _project_runtime_topology(
    graph: UnifiedGraph,
    inputs: GraphBuildInput,
    indexes: BuildIndexes,
    report: dict[str, Any],
    tenant_id: str,
) -> None:
    ai_inventory = report.get("ai_inventory", {})
    if isinstance(ai_inventory, dict):
        _add_framework_topology(
            graph, ai_inventory.get("framework_agents", []), inputs.data_source, host_agent_id=_project_host_agent_id(graph, inputs.agents)
        )
        _add_ai_stack_frameworks(graph, ai_inventory, inputs.data_source)
    _add_cross_env_correlation(graph, inputs.agents, inputs.data_source)
    project_runtime_session(graph, report.get("runtime_session_graph"))
    _add_agentic_identity_graph_projections(graph, report, inputs.data_source, tenant_id)
    _add_runtime_incident_feedback(graph, report, indexes.agent_name_to_ids, inputs.data_source)
    project_report_trace_events(graph, report.get("runtime_trace_events"), tenant_id)
    project_recorded_activity(graph, report.get("runtime_activity_events"), tenant_id)


def _project_cloud_authority(
    graph: UnifiedGraph,
    inventories: list[dict[str, Any]],
    report: dict[str, Any],
    data_source: str,
) -> None:
    for inventory in inventories:
        _add_cloud_role_assignments(graph, inventory, data_source)
        apply_authorization_evidence(graph, inventory)
        _add_gcp_organization(
            graph,
            inventory.get("gcp_organization"),
            data_source,
            allow_heuristic_authorization=not has_authoritative_authorization_evidence(inventory),
        )
    _add_aws_organization(graph, report.get("aws_organization"), data_source)
    _add_cloud_org_architecture_findings(graph, report, data_source)
    _add_snowflake_source_lanes(graph, report, data_source)
    audit = report.get("cloud_audit_trail")
    if isinstance(audit, list):
        for provider_audit in audit:
            _add_cloud_audit_behavioral(graph, provider_audit, data_source)
    else:
        _add_cloud_audit_behavioral(graph, audit, data_source)


def _analysis_ports() -> GraphAnalysisPorts:
    return GraphAnalysisPorts(
        runtime_evidence=_apply_runtime_evidence_overlay,
        repo_structure=_apply_repo_structure_overlay,
        ast_tool=_apply_ast_tool_overlay,
        code_graph=_apply_code_graph_overlay,
        repo_trust=_apply_repo_trust_overlay,
        ci_graph=_apply_ci_graph_overlay,
        agent_reach_risk=_apply_agent_reach_risk,
        aspm=_apply_aspm_overlay,
        cost=_apply_cost_overlay,
    )


def _add_cloud_inventory(graph: UnifiedGraph, inventory: Any, data_source: str) -> None:
    """Promote estate-wide cloud inventory into first-class graph nodes.

    Consumes the payload produced by
    :func:`agent_bom.cloud.aws_inventory.discover_inventory` (stored under
    ``report_json["cloud_inventory"]``) and emits:

    - S3 buckets   → ``CLOUD_RESOURCE`` carrying ``resource_kind="s3-bucket"`` and
      a data-store-signalling label, so the CNAPP overlay attaches a
      ``DATA_STORE`` companion (via ``STORES``) and ``EXPOSED_TO`` when public —
      the path the DSPM tiers consume.
    - EC2 instances + security groups → ``CLOUD_RESOURCE``; an instance is linked
      ``EXPOSED_TO`` an internet-facing security group, and the group carries the
      structured ``network_exposure`` the CNAPP overlay reads.
    - IAM roles / users → identity principal nodes with attached ``POLICY`` nodes
      (``ATTACHED``) and trust principals (``TRUSTS`` / ``CROSS_ACCOUNT_TRUST``),
      plus ``CAN_ACCESS`` edges to the account's resources, so the
      effective-permissions overlay resolves ``HAS_PERMISSION``.

    Missing / empty / non-ok inventory is a no-op; imported data retains its source tag.
    """
    if not isinstance(inventory, dict) or inventory.get("status") != "ok":
        return
    # The provider translation below rebuilds an AWS-shaped dict and drops the
    # data/secret/registry/network collections; keep the original to ingest them
    # through the normalized resource model.
    original_inventory = inventory
    allow_heuristic_authorization = not has_authoritative_authorization_evidence(original_inventory)
    inventory = _normalize_cloud_inventory(inventory)
    provider = _clean_graph_part(inventory.get("provider")) or "aws"
    account_id = _clean_graph_part(inventory.get("account_id"))
    region = _clean_graph_part(inventory.get("region"))
    data_sources = cloud_inventory_sources(original_inventory, data_source, provider)

    provider_node_id = f"provider:{provider}"
    graph.add_node(
        UnifiedNode(
            id=provider_node_id,
            entity_type=EntityType.PROVIDER,
            label=provider,
            attributes={"provider": provider, "source": "cloud-inventory"},
            data_sources=data_sources,
        )
    )
    account_node_id = ""
    if account_id:
        account_node_id = _identity_node_id(EntityType.ACCOUNT, provider, account_id)
        graph.add_node(
            UnifiedNode(
                id=account_node_id,
                entity_type=EntityType.ACCOUNT,
                label=account_id,
                attributes={"account_id": account_id, "cloud_provider": provider, "source": "cloud-inventory"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )

    resource_ids: list[str] = []

    project_side_scan_targets(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    project_buckets(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    project_databases(
        graph,
        original_inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    sg_node_by_id = project_security_groups(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    instance_nodes = project_instances(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
        sg_node_by_id=sg_node_by_id,
    )

    # GCP rule applicability uses network and target scope. Recorded bindings
    # remain distinct from assessed network reachability.
    if provider == "gcp":
        _apply_gcp_firewall_exposure(graph, sg_node_by_id, instance_nodes)

    instance_node_by_id: dict[str, str] = {}
    for inst_node_id, instance in instance_nodes:
        iid = _clean_graph_part(instance.get("instance_id")) or _clean_graph_part(instance.get("id"))
        if iid:
            instance_node_by_id[iid] = inst_node_id

    internet_facing_lbs = project_aws_services(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )
    project_gcp_services(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )

    # ── Data / secret / registry / network resources (normalized model) ──
    _add_normalized_cloud_resources(
        graph,
        original_inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
    )

    # ── Network edge: WAF, API gateways, ENIs/NICs, subnets, NAT/IGW, IPs ──
    _add_network_edge_inventory(
        graph,
        inventory,
        provider=provider,
        account_id=account_id,
        account_node_id=account_node_id,
        region=region,
        data_sources=data_sources,
        resource_ids=resource_ids,
        sg_node_by_id=sg_node_by_id,
        instance_node_by_id=instance_node_by_id,
    )
    _link_internet_facing_load_balancers(graph, internet_facing_lbs, instance_nodes)

    # ── Management-group hierarchy (org → subscription CONTAINS tree) ──
    _add_management_group_hierarchy(graph, original_inventory, provider=provider, data_sources=data_sources)

    # ── IAM roles + users → identity principals (CAN_ACCESS resources) ──
    for principal in [*(inventory.get("roles", []) or []), *(inventory.get("users", []) or [])]:
        if isinstance(principal, dict):
            _add_inventory_principal(
                graph,
                principal,
                provider=provider,
                account_node_id=account_node_id,
                resource_ids=resource_ids,
                data_sources=data_sources,
                allow_heuristic_authorization=allow_heuristic_authorization,
            )

    _wire_instance_profile_roles(
        graph,
        inventory,
        provider=provider,
        instance_node_by_id=instance_node_by_id,
    )

    # ── IAM / Entra groups → GROUP nodes + MEMBER_OF edges from members ──
    # A group carries its members' shared access (its attached policies / bound
    # roles). Wiring the group as a principal with CAN_ACCESS, plus MEMBER_OF
    # edges from each member, lets the effective-permissions overlay attribute
    # group-granted access to the member — group-based access is one of the most
    # common privilege paths and was invisible before.
    for group in inventory.get("groups", []) or []:
        if isinstance(group, dict):
            _add_inventory_group(
                graph,
                group,
                provider=provider,
                account_node_id=account_node_id,
                resource_ids=resource_ids,
                data_sources=data_sources,
                allow_heuristic_authorization=allow_heuristic_authorization,
            )


def _account_scoped_principal(principal: dict[str, Any], principal_id: str, account_node_id: str) -> str:
    """A bare name is unique only inside its account; an ARN already names the account."""
    if principal.get("arn") or not account_node_id:
        return principal_id
    return f"{account_node_id.split(':', 2)[-1]}/{principal_id}"


def _add_inventory_principal(
    graph: UnifiedGraph,
    principal: dict[str, Any],
    *,
    provider: str,
    account_node_id: str,
    resource_ids: list[str],
    data_sources: list[str],
    allow_heuristic_authorization: bool = True,
) -> None:
    """Emit one IAM role/user as an identity principal with policy + access edges."""
    principal_type = _clean_graph_part(principal.get("principal_type")) or "user"
    principal_id = _clean_graph_part(principal.get("arn")) or _clean_graph_part(principal.get("name"))
    principal_name = _clean_graph_part(principal.get("name")) or principal_id
    if not principal_id:
        return
    entity_type = _identity_entity_type(principal_type)
    principal_node_id = _identity_node_id(entity_type, provider, _account_scoped_principal(principal, principal_id, account_node_id))
    node_attributes: dict[str, Any] = {
        "principal_id": principal_id,
        "principal_name": principal_name,
        "principal_type": principal_type,
        "directory_principal_id": _clean_graph_part(principal.get("principal_id")),
        "principal_email": _clean_graph_part(principal.get("email")),
        "principal_resource_id": _clean_graph_part(principal.get("arn")),
        "cloud_provider": provider,
        "privilege_level": _clean_graph_part(principal.get("privilege_level")) or "unknown",
        "iam_path": _clean_graph_part(principal.get("path")),
        "source": "cloud-inventory",
    }
    # Thread collected role usage evidence so NHI governance dormancy uses a real
    # last-used signal. Only a real timestamp sets ``last_used_at`` — absent
    # telemetry leaves the field unset so dormancy stays fail-closed.
    usage_evidence = principal.get("usage_evidence")
    if isinstance(usage_evidence, Mapping):
        state = usage_evidence.get("state")
        if isinstance(state, str) and state.strip():
            node_attributes["usage_evidence_state"] = state
        last_used = _role_last_used_at(usage_evidence)
        if last_used:
            node_attributes["last_used_at"] = last_used
    graph.add_node(
        UnifiedNode(
            id=principal_node_id,
            entity_type=entity_type,
            label=principal_name,
            attributes=node_attributes,
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
        )
    )
    if account_node_id:
        graph.add_edge(
            UnifiedEdge(
                source=principal_node_id,
                target=account_node_id,
                relationship=RelationshipType.MEMBER_OF,
                evidence={"source": "cloud-inventory", "principal_type": principal_type},
            )
        )

    # Attached policies (privilege already classified by the scanner).
    for policy in _policy_entries(principal):
        policy_node_id = _identity_node_id(EntityType.POLICY, provider, policy["id"])
        graph.add_node(
            UnifiedNode(
                id=policy_node_id,
                entity_type=EntityType.POLICY,
                label=policy["name"],
                attributes={
                    "policy_id": policy["id"],
                    "policy_name": policy["name"],
                    "privilege_level": policy.get("privilege_level", "unknown"),
                    "cloud_provider": provider,
                    **_policy_document_attrs(policy),
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=principal_node_id,
                target=policy_node_id,
                relationship=RelationshipType.ATTACHED,
                evidence={"source": "cloud-inventory", "principal_type": principal_type},
            )
        )

    # Trust principals from the AssumeRole policy document.
    for trust in _trust_entries(principal):
        trust_entity_type = _identity_entity_type(trust["type"])
        trust_node_id = _identity_node_id(trust_entity_type, provider, trust["id"])
        graph.add_node(
            UnifiedNode(
                id=trust_node_id,
                entity_type=trust_entity_type,
                label=trust["name"],
                attributes={
                    "principal_id": trust["id"],
                    "principal_name": trust["name"],
                    "principal_type": trust["type"],
                    "cloud_provider": provider,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        relationship = (
            RelationshipType.CROSS_ACCOUNT_TRUST
            if trust["relationship"] == RelationshipType.CROSS_ACCOUNT_TRUST.value
            else RelationshipType.TRUSTS
        )
        graph.add_edge(
            UnifiedEdge(
                source=principal_node_id,
                target=trust_node_id,
                relationship=relationship,
                evidence={
                    "source": "cloud-inventory",
                    "principal_type": principal_type,
                    "trusted_principal_type": trust["type"],
                    "source_field": trust["source_field"],
                },
            )
        )

    # AWS Access-Advisor right-sizing evidence: each service the principal is
    # granted, carrying its last-used timestamp (or None = never used), as a
    # HAS_PERMISSION grant edge the CIEM over-privilege emitter reads.
    _add_access_advisor_grants(
        graph,
        principal,
        principal_node_id=principal_node_id,
        provider=provider,
        data_sources=data_sources,
    )

    # Direct access to the account's inventoried resources. The effective-
    # permissions overlay turns CAN_ACCESS (+ assume/trust chains) into the
    # HAS_PERMISSION transitive closure; admin-privileged principals reach
    # every resource, others get a baseline same-account access edge.
    privilege = _clean_graph_part(principal.get("privilege_level")) or "unknown"
    if allow_heuristic_authorization and privilege in ("admin", "write"):
        for resource_id in resource_ids:
            graph.add_edge(
                UnifiedEdge(
                    source=principal_node_id,
                    target=resource_id,
                    relationship=RelationshipType.CAN_ACCESS,
                    evidence={"source": "cloud-inventory", "basis": f"{privilege}_privilege"},
                )
            )


def _add_inventory_group(
    graph: UnifiedGraph,
    group: dict[str, Any],
    *,
    provider: str,
    account_node_id: str,
    resource_ids: list[str],
    data_sources: list[str],
    allow_heuristic_authorization: bool = True,
) -> None:
    """Emit one IAM/Entra group as a ``GROUP`` node with policies + membership.

    The group node carries its attached/bound policies (``ATTACHED``) and, when
    it is admin/write-privileged, a ``CAN_ACCESS`` edge to each inventoried
    resource — the same baseline the effective-permissions overlay applies to a
    user/role. ``MEMBER_OF`` edges run from each member principal to the group so
    the overlay attributes group-granted access to the member. Members are created
    as thin nodes when a per-principal scan has not already added them.
    """
    group_id = _clean_graph_part(group.get("arn")) or _clean_graph_part(group.get("name"))
    if not group_id:
        return
    group_name = _clean_graph_part(group.get("name")) or group_id
    group_node_id = _identity_node_id(EntityType.GROUP, provider, _account_scoped_principal(group, group_id, account_node_id))
    privilege = _clean_graph_part(group.get("privilege_level")) or "unknown"
    graph.add_node(
        UnifiedNode(
            id=group_node_id,
            entity_type=EntityType.GROUP,
            label=group_name,
            attributes={
                "principal_id": group_id,
                "principal_resource_id": _clean_graph_part(group.get("arn")),
                "directory_principal_id": _clean_graph_part(group.get("principal_id")),
                "principal_name": group_name,
                "principal_type": "group",
                "cloud_provider": provider,
                "privilege_level": privilege,
                "iam_path": _clean_graph_part(group.get("path")),
                "source": "cloud-inventory",
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
        )
    )
    if account_node_id:
        _add_rel_edge(
            graph, group_node_id, account_node_id, RelationshipType.MEMBER_OF, {"source": "cloud-inventory", "principal_type": "group"}
        )

    # Group-attached policies (privilege already classified by the scanner).
    for policy in _policy_entries(group):
        policy_node_id = _add_identity_node(
            graph,
            EntityType.POLICY,
            policy["id"],
            provider,
            data_sources,
            label=policy["name"],
            policy_id=policy["id"],
            policy_name=policy["name"],
            privilege_level=policy.get("privilege_level", "unknown"),
            cloud_provider=provider,
            **_policy_document_attrs(policy),
        )
        _add_rel_edge(
            graph, group_node_id, policy_node_id, RelationshipType.ATTACHED, {"source": "cloud-inventory", "principal_type": "group"}
        )

    # Legacy privilege inference remains separate from authoritative grants.
    if allow_heuristic_authorization and privilege in ("admin", "write"):
        for resource_id in resource_ids:
            _add_rel_edge(
                graph,
                group_node_id,
                resource_id,
                RelationshipType.CAN_ACCESS,
                {"source": "cloud-inventory", "basis": f"{privilege}_privilege"},
            )

    # Preserve native member IDs even when only directory membership was collected.
    for member in group.get("members", []) or []:
        if not isinstance(member, dict):
            continue
        member_id = _clean_graph_part(member.get("id"))
        if not member_id:
            continue
        member_entity = _identity_entity_type(_clean_graph_part(member.get("type")) or "user")
        member_node_id = _identity_node_id(member_entity, provider, member_id)
        if member_node_id not in graph.nodes:
            _add_identity_node(
                graph,
                member_entity,
                member_id,
                provider,
                data_sources,
                label=_clean_graph_part(member.get("name")) or member_id,
                principal_id=member_id,
                directory_principal_id=member_id,
                principal_name=_clean_graph_part(member.get("name")) or member_id,
                principal_type=_clean_graph_part(member.get("type")) or "user",
                cloud_provider=provider,
                source="cloud-inventory",
            )
        _add_rel_edge(
            graph, member_node_id, group_node_id, RelationshipType.MEMBER_OF, {"source": "cloud-inventory", "membership": "group"}
        )


# Provider prefixes stripped when fingerprinting a model reference so that
# ``openai:gpt-4o``, ``openai/gpt-4o`` and ``gpt-4o`` collapse to one node.
