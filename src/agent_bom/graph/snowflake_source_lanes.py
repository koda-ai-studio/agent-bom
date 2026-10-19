"""Snowflake source lanes for unified graph construction."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agent_bom.graph.builder_snowflake_data_movement import _add_snowflake_exfil, _add_snowflake_external_data
from agent_bom.graph.builder_snowflake_governance import _add_snowflake_activity, _add_snowflake_governance
from agent_bom.graph.builder_snowflake_lane import _needs_account_scope
from agent_bom.graph.builder_snowflake_objects import _add_snowflake_identity, _add_snowflake_object_graph
from agent_bom.graph.builder_snowflake_platform import _add_snowflake_integrations, _add_snowflake_pipeline, _add_snowflake_services
from agent_bom.graph.builder_snowflake_platform import _add_snowflake_organization as _add_snowflake_organization
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _add_snowflake_source_lanes(graph: UnifiedGraph, report_json: dict[str, Any], data_source: str) -> None:
    """Stage account-local lanes before any same-name nodes can merge.

    Single-account reports retain their existing node IDs. Mixed or missing
    account scopes get separate local IDs; labels and FQNs are never account
    equivalence evidence. Original persisted snapshots are not rewritten.
    """
    scopes = _snowflake_scopes(report_json)

    if not scopes:
        return
    from contextlib import nullcontext
    from copy import deepcopy

    from agent_bom.graph.store_backed import StoreBackedUnifiedGraph, open_store_backed_unified_graph

    store_backed = isinstance(graph, StoreBackedUnifiedGraph)
    for scope, lanes in scopes.items():
        stage_context = (
            open_store_backed_unified_graph(scan_id=graph.scan_id, tenant_id=graph.tenant_id, created_at=graph.created_at, backend="sqlite")
            if store_backed
            else nullcontext(UnifiedGraph(scan_id=graph.scan_id, tenant_id=graph.tenant_id, created_at=graph.created_at))
        )
        with stage_context as staged:
            _project_snowflake_lanes(staged, lanes, data_source)
            remap: dict[str, str] = {}
            account = scope[1] if scope[0] == "account" else ""
            for staged_node in staged.nodes.values():
                # Store-backed cached identities must retain their original key.
                # Clone only the current output node, never the whole graph.
                node = deepcopy(staged_node) if store_backed else staged_node
                original_id = node.id
                provider = _clean_graph_part(node.attributes.get("cloud_provider") or node.dimensions.cloud_provider)
                account_local = provider == "snowflake" and _needs_account_scope(node, account)
                if account_local:
                    node.attributes["snowflake_local_id"] = original_id
                    node.attributes["snowflake_scope_version"] = "account-lanes.v1"
                    if account:
                        node.attributes["account_id"] = account
                    existing = graph.nodes.get(original_id)
                    collides = existing is not None and (not account or _clean_graph_part(existing.attributes.get("account_id")) != account)
                    if len(scopes) > 1 or collides:
                        # Content framing and SHA-256 preserve case and separators;
                        # stable_node_id lowercases its inputs and is unsuitable for
                        # quoted Snowflake identifiers or unproven account aliases.
                        key = json.dumps([*scope, original_id], separators=(",", ":"))
                        suffix = hashlib.sha256(key.encode()).hexdigest()
                        node.id = f"{node.entity_type.value}:snowflake:scoped:{suffix}"
                        node.attributes["legacy_graph_id"] = original_id
                if store_backed:
                    # Persist the mapping in the private staging workspace so
                    # a large source does not retain an O(nodes) remap in RAM.
                    staged_node.attributes["_snowflake_projection_id"] = node.id
                else:
                    remap[original_id] = node.id
                graph.add_node(node)
            for edge in staged.edges:
                if store_backed:
                    source = staged.nodes[edge.source].attributes["_snowflake_projection_id"]
                    target = staged.nodes[edge.target].attributes["_snowflake_projection_id"]
                else:
                    source = remap[edge.source]
                    target = remap[edge.target]
                graph.add_edge(edge.with_endpoints(source, target))
            graph.analysis_status.update(staged.analysis_status)


def _project_snowflake_lanes(graph: UnifiedGraph, report_json: dict[str, Any], data_source: str) -> None:
    """Project lanes sharing one explicitly recorded account (or one unknown source)."""
    _add_snowflake_object_graph(graph, report_json.get("snowflake_object_graph"), data_source)
    _add_snowflake_exfil(graph, report_json.get("snowflake_exfil_graph"), data_source)
    _add_snowflake_identity(
        graph,
        report_json.get("snowflake_login_anomalies"),
        report_json.get("snowflake_auth_posture"),
        data_source,
    )
    _add_snowflake_services(graph, report_json.get("snowflake_services"), data_source)
    _sf_services_payload = report_json.get("snowflake_services")
    _add_snowflake_organization(
        graph,
        _sf_services_payload.get("organization") if isinstance(_sf_services_payload, dict) else None,
        data_source,
    )
    _add_snowflake_pipeline(graph, report_json.get("snowflake_pipeline"), data_source)
    _add_snowflake_integrations(graph, report_json.get("snowflake_integrations"), data_source)
    _add_snowflake_external_data(graph, report_json.get("snowflake_external_data"), data_source)
    _add_snowflake_governance(graph, report_json.get("snowflake_governance"), data_source)
    _add_snowflake_activity(graph, report_json.get("snowflake_activity"), data_source)


def _snowflake_scopes(report_json: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    lane_keys = (
        "snowflake_object_graph",
        "snowflake_exfil_graph",
        "snowflake_login_anomalies",
        "snowflake_auth_posture",
        "snowflake_services",
        "snowflake_pipeline",
        "snowflake_integrations",
        "snowflake_external_data",
        "snowflake_governance",
        "snowflake_activity",
    )
    scopes: dict[tuple[str, str], dict[str, Any]] = {}
    for key in lane_keys:
        payload = report_json.get(key)
        if not isinstance(payload, dict):
            continue
        organization = payload.get("organization") if key == "snowflake_services" else None
        # Organization collection has its own status; retain that independent
        # evidence even when the containing services inventory is unavailable.
        organization_ok = isinstance(organization, dict) and organization.get("status") == "ok"
        if payload.get("status") != "ok" and not organization_ok:
            continue
        account = _clean_graph_part(payload.get("account"))
        scope = ("account", account) if account else ("source", key)
        scopes.setdefault(scope, {})[key] = payload

    return scopes
