"""AWS organization hierarchy, account and service-control policy projection."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.cloud_context import _add_identity_node, _prepare_cloud_payload
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _add_aws_organization(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote the AWS Organization (org → OUs → accounts → SCPs) into the graph.

    The multi-account estate as a navigable ``CONTAINS`` hierarchy: org → OU →
    account, with SCPs ``GOVERNS``-linked to the OUs/accounts they bound. Account
    nodes use the same ``account:aws:<id>`` id a per-account scan emits, so the
    org structure and any inventoried account graph stitch together. Scales to
    thousands of accounts. Never raises; non-ok payload is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "aws-organizations")
    if prepared is None:
        return
    _, data_sources = prepared
    org_id = _clean_graph_part(payload.get("org_id"))
    org_node_id = f"org:aws:{org_id}" if org_id else "org:aws:organization"
    graph.add_node(
        UnifiedNode(
            id=org_node_id,
            entity_type=EntityType.ORG,
            label=f"AWS org: {org_id or 'organization'}",
            attributes={
                "org_id": org_id,
                "cloud_provider": "aws",
                "master_account_id": _clean_graph_part(payload.get("master_account_id")),
                "feature_set": _clean_graph_part(payload.get("feature_set")),
                **({"architecture": payload.get("architecture")} if isinstance(payload.get("architecture"), dict) else {}),
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider="aws", surface="identity"),
        )
    )

    _project_aws_units(graph, payload, data_sources, org_node_id)
    _project_aws_accounts(graph, payload, data_sources, org_node_id)
    _project_aws_scps(graph, payload, data_sources, org_node_id)


def _ou_node_id(ou_id: str) -> str:
    return f"org:aws:ou:{ou_id}"


def _project_aws_units(graph: UnifiedGraph, payload: dict[str, Any], data_sources: list[str], org_node_id: str) -> None:
    for ou in payload.get("organizational_units", []) or []:
        if not isinstance(ou, dict):
            continue
        ou_id = _clean_graph_part(ou.get("id"))
        if not ou_id:
            continue
        node_id = _ou_node_id(ou_id)
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.ORG,
                label=f"{'root' if ou.get('is_root') else 'OU'}: {_clean_graph_part(ou.get('name')) or ou_id}",
                attributes={"ou_id": ou_id, "is_root": bool(ou.get("is_root")), "cloud_provider": "aws"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="aws", surface="identity"),
            )
        )
        parent = _clean_graph_part(ou.get("parent_id"))
        parent_node = _ou_node_id(parent) if parent else org_node_id
        _add_rel_edge(graph, parent_node, node_id, RelationshipType.CONTAINS, {"source": "aws-organizations"})


def _project_aws_accounts(graph: UnifiedGraph, payload: dict[str, Any], data_sources: list[str], org_node_id: str) -> None:
    for acct in payload.get("accounts", []) or []:
        if not isinstance(acct, dict):
            continue
        acct_id = _clean_graph_part(acct.get("id"))
        if not acct_id:
            continue
        acct_node = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            acct_id,
            "aws",
            data_sources,
            label=f"account: {_clean_graph_part(acct.get('name')) or acct_id}",
            account_id=acct_id,
            cloud_provider="aws",
            account_name=_clean_graph_part(acct.get("name")),
            account_status=_clean_graph_part(acct.get("status")),
        )
        ou_id = _clean_graph_part(acct.get("ou_id"))
        parent_node = _ou_node_id(ou_id) if ou_id else org_node_id
        _add_rel_edge(graph, parent_node, acct_node, RelationshipType.CONTAINS, {"source": "aws-organizations"})


def _project_aws_scps(graph: UnifiedGraph, payload: dict[str, Any], data_sources: list[str], org_node_id: str) -> None:
    for scp in payload.get("scps", []) or []:
        if not isinstance(scp, dict):
            continue
        scp_id = _clean_graph_part(scp.get("id"))
        if not scp_id:
            continue
        scp_node = f"policy:aws:scp:{scp_id}"
        graph.add_node(
            UnifiedNode(
                id=scp_node,
                entity_type=EntityType.POLICY,
                label=f"SCP: {_clean_graph_part(scp.get('name')) or scp_id}",
                attributes={"scp_id": scp_id, "aws_managed": bool(scp.get("aws_managed")), "cloud_provider": "aws"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="aws", surface="identity"),
            )
        )
        _add_rel_edge(graph, org_node_id, scp_node, RelationshipType.OWNS, {"source": "aws-organizations"})
        for target in scp.get("targets", []) or []:
            target = _clean_graph_part(target)
            if not target:
                continue
            # A target is an OU id, the root id, or a 12-digit account id.
            tgt_node = _identity_node_id(EntityType.ACCOUNT, "aws", target) if target.isdigit() else _ou_node_id(target)
            if tgt_node in graph.nodes:
                _add_rel_edge(graph, scp_node, tgt_node, RelationshipType.GOVERNS, {"source": "aws-organizations"})
