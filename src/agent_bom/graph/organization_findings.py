"""Organization findings for unified graph construction."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _add_cloud_org_architecture_findings(graph: UnifiedGraph, report_json: Mapping[str, Any], data_source: str) -> None:
    """Promote org-architecture findings (single-account / flat hierarchy) to MISCONFIGURATION nodes.

    Reads ``aws_organization.findings`` and nested ``cloud_inventory[].gcp_organization.findings``.
    Works even when status is ``not_in_org`` (hierarchy builder no-ops) so the architecture
    verdict still lands on the graph. Does not invent CIS tags.
    """
    payloads: list[tuple[str, dict[str, Any]]] = []
    aws_org = report_json.get("aws_organization")
    if isinstance(aws_org, dict):
        payloads.append(("aws", aws_org))

    inventory = report_json.get("cloud_inventory")
    inv_list = inventory if isinstance(inventory, list) else ([inventory] if isinstance(inventory, dict) else [])
    for entry in inv_list:
        if not isinstance(entry, dict):
            continue
        gcp_org = entry.get("gcp_organization")
        if isinstance(gcp_org, dict):
            payloads.append(("gcp", gcp_org))

    for provider, payload in payloads:
        _project_org_findings(graph, provider, payload, data_source)


def _project_org_findings(graph: UnifiedGraph, provider: str, payload: dict[str, Any], data_source: str) -> None:
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return
    org_id = _clean_graph_part(payload.get("org_id"))
    if provider == "aws":
        target_id = f"org:aws:{org_id}" if org_id else "org:aws:standalone"
        target_label = f"AWS org: {org_id or 'standalone account'}"
    else:
        target_id = f"org:gcp:{org_id}" if org_id else "org:gcp:standalone"
        target_label = f"GCP org: {org_id or 'standalone project'}"

    # Ensure a target ORG node exists even for not_in_org (hierarchy layer skipped).
    if target_id not in graph.nodes:
        arch = payload.get("architecture") if isinstance(payload.get("architecture"), dict) else {}
        graph.add_node(
            UnifiedNode(
                id=target_id,
                entity_type=EntityType.ORG,
                label=target_label,
                attributes={
                    "org_id": org_id,
                    "cloud_provider": provider,
                    "status": _clean_graph_part(payload.get("status")),
                    **({"architecture": arch} if arch else {}),
                },
                data_sources=sorted({data_source, f"{provider}-organizations"} - {""}),
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )

    for raw in findings:
        if not isinstance(raw, dict):
            continue
        check_id = _clean_graph_part(raw.get("check_id")) or _clean_graph_part(raw.get("title"))
        if not check_id:
            continue
        misconfig_id = f"misconfig:cloud-org:{provider}:{check_id}"
        if misconfig_id in graph.nodes:
            continue
        graph.add_node(
            UnifiedNode(
                id=misconfig_id,
                entity_type=EntityType.MISCONFIGURATION,
                label=_clean_graph_part(raw.get("title")) or check_id,
                severity=str(raw.get("severity") or "medium").lower(),
                attributes={
                    "check_id": check_id,
                    "category": _clean_graph_part(raw.get("category")) or "estate_architecture",
                    "evidence": _clean_graph_part(raw.get("detail")),
                    "cloud_provider": provider,
                    "account_count": raw.get("account_count"),
                    "hierarchy_depth": raw.get("hierarchy_depth"),
                },
                compliance_tags=[f"CLOUD-ORG-{check_id}"],
                data_sources=sorted({data_source, f"{provider}-organizations"} - {""}),
                dimensions=NodeDimensions(cloud_provider=provider),
            )
        )
        _add_rel_edge(graph, misconfig_id, target_id, RelationshipType.AFFECTS, edge_evidence(f"{provider}-organizations", "static_scan"))
