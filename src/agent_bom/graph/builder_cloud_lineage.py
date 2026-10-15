"""Cloud-origin lineage stages for agents discovered from cloud providers.

``_add_agent_cloud_lineage`` in ``builder`` resolves a ``_CloudLineage`` from
``agent.metadata.cloud_origin`` and then runs these stages: provider and
resource nodes, org/account scope edges, and the cloud principal with its
attached policies and trust relationships.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_bom.graph.cloud_context import (
    _add_identity_node,
    _first_cloud_scope_value,
    _identity_entity_type,
    _policy_document_attrs,
    _policy_entries,
    _trust_entries,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


@dataclass(frozen=True)
class _CloudLineage:
    origin: dict[str, Any]
    provider: str
    service: str
    resource_type: str
    resource_id: str
    resource_name: str
    location: str
    data_sources: list[str]
    org_key: str
    org_id: str
    account_key: str
    account_id: str

    @property
    def cloud_provider_id(self) -> str:
        return f"provider:{self.provider}"

    @property
    def resource_node_id(self) -> str:
        return f"cloud_resource:{self.provider}:{self.service}:{self.resource_type}:{self.resource_id}"

    @property
    def org_node_id(self) -> str:
        return _identity_node_id(EntityType.ORG, self.provider, self.org_id) if self.org_id else ""

    @property
    def account_node_id(self) -> str:
        return _identity_node_id(EntityType.ACCOUNT, self.provider, self.account_id) if self.account_id else ""


def _resolve_cloud_lineage(agent_dict: dict[str, Any], origin: dict[str, Any], data_source: str) -> _CloudLineage | None:
    # Cloud sources are conventionally named `<provider>-<service>` (e.g.
    # "aws-bedrock", "azure-openai", "gcp-vertex-ai") so we can recover the
    # service name from the agent's `source` field when `cloud_origin` lacks
    # it. This mirrors the secondary fallback chain that `provider` already
    # uses and avoids the literal "unknown-service" placeholder leaking into
    # the graph just because one cloud discoverer forgot to populate the
    # service slot.
    raw_source = str(agent_dict.get("source") or "").strip()
    source_service_fallback = raw_source.split("-", 1)[1] if "-" in raw_source else ""

    provider = _clean_graph_part(origin.get("provider")) or _clean_graph_part(raw_source) or "cloud"
    service = _clean_graph_part(origin.get("service")) or _clean_graph_part(source_service_fallback) or "unknown-service"
    resource_type = _clean_graph_part(origin.get("resource_type")) or "resource"
    resource_id = _clean_graph_part(origin.get("resource_id")) or _clean_graph_part(origin.get("resource_name"))
    if not resource_id:
        return None
    scope = origin.get("scope", {})
    if not isinstance(scope, dict):
        scope = {}
    org_key, org_id = _first_cloud_scope_value(scope, "org_id", "organization_id", "management_group_id")
    account_key, account_id = _first_cloud_scope_value(
        scope,
        "account_id",
        "aws_account_id",
        "subscription_id",
        "project_id",
        "tenant_id",
    )
    account_id = account_id or _clean_graph_part(origin.get("account_id")) or _clean_graph_part(origin.get("subscription_id"))
    return _CloudLineage(
        origin=origin,
        provider=provider,
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=_clean_graph_part(origin.get("resource_name")) or resource_id,
        location=_clean_graph_part(origin.get("location")),
        data_sources=sorted({data_source, str(agent_dict.get("source") or "").strip(), f"cloud:{provider}"} - {""}),
        org_key=org_key,
        org_id=org_id,
        account_key=account_key,
        account_id=account_id,
    )


def _add_lineage_resource_nodes(graph: UnifiedGraph, lineage: _CloudLineage, agent_metadata: dict[str, Any]) -> None:
    graph.add_node(
        UnifiedNode(
            id=lineage.cloud_provider_id,
            entity_type=EntityType.PROVIDER,
            label=lineage.provider,
            attributes={"provider": lineage.provider, "source": "cloud_origin"},
            data_sources=lineage.data_sources,
        )
    )
    graph.add_node(
        UnifiedNode(
            id=lineage.resource_node_id,
            entity_type=EntityType.CLOUD_RESOURCE,
            label=lineage.resource_name,
            attributes={
                "resource_id": lineage.resource_id,
                "resource_name": lineage.resource_name,
                "resource_type": lineage.resource_type,
                "cloud_provider": lineage.provider,
                "cloud_service": lineage.service,
                "location": lineage.location,
                "scope": lineage.origin.get("scope", {}),
                "network": lineage.origin.get("network", {}),
                "cloud_origin": lineage.origin,
                "cloud_state": agent_metadata.get("cloud_state"),
                "cloud_scope": agent_metadata.get("cloud_scope"),
                "cloud_timestamps": agent_metadata.get("cloud_timestamps"),
            },
            data_sources=lineage.data_sources,
            dimensions=NodeDimensions(cloud_provider=lineage.provider, surface=lineage.service),
        )
    )


def _add_lineage_org(graph: UnifiedGraph, lineage: _CloudLineage) -> None:
    provider, org_id, org_key = lineage.provider, lineage.org_id, lineage.org_key
    _add_identity_node(
        graph,
        EntityType.ORG,
        org_id,
        provider,
        lineage.data_sources,
        label=org_id,
        org_id=org_id,
        scope_key=org_key,
        cloud_provider=provider,
        cloud_origin=lineage.origin,
    )
    _add_rel_edge(
        graph,
        lineage.cloud_provider_id,
        lineage.org_node_id,
        RelationshipType.HOSTS,
        {"source": "cloud_origin", "provider": provider, "scope_key": org_key},
    )


def _add_lineage_account(graph: UnifiedGraph, lineage: _CloudLineage) -> None:
    provider, account_id, account_node_id = lineage.provider, lineage.account_id, lineage.account_node_id
    scope_key = lineage.account_key or "account_id"
    _add_identity_node(
        graph,
        EntityType.ACCOUNT,
        account_id,
        provider,
        lineage.data_sources,
        label=account_id,
        account_id=account_id,
        scope_key=scope_key,
        cloud_provider=provider,
        cloud_origin=lineage.origin,
    )
    scope_evidence = {"source": "cloud_origin", "provider": provider, "scope_key": scope_key}
    _add_rel_edge(graph, lineage.cloud_provider_id, account_node_id, RelationshipType.HOSTS, dict(scope_evidence))
    if lineage.org_node_id:
        _add_rel_edge(
            graph,
            account_node_id,
            lineage.org_node_id,
            RelationshipType.PART_OF,
            {"source": "cloud_origin", "provider": provider, "scope_key": lineage.org_key},
        )
    _add_rel_edge(graph, account_node_id, lineage.resource_node_id, RelationshipType.HOSTS, dict(scope_evidence))
    _add_rel_edge(graph, account_node_id, lineage.resource_node_id, RelationshipType.CONTAINS, dict(scope_evidence))


def _add_lineage_scope_edges(graph: UnifiedGraph, lineage: _CloudLineage, agent_id: str) -> None:
    if lineage.org_node_id:
        _add_lineage_org(graph, lineage)
    if lineage.account_node_id:
        _add_lineage_account(graph, lineage)
    _add_rel_edge(
        graph,
        lineage.cloud_provider_id,
        lineage.resource_node_id,
        RelationshipType.HOSTS,
        {"source": "cloud_origin", "provider": lineage.provider, "service": lineage.service},
    )
    _add_rel_edge(
        graph,
        agent_id,
        lineage.resource_node_id,
        RelationshipType.HOSTED_ON,
        {"source": "cloud_origin", "resource_id": lineage.resource_id},
    )


def _add_principal_policies(graph: UnifiedGraph, lineage: _CloudLineage, principal: dict[str, Any], principal_node_id: str) -> None:
    principal_type = principal.get("principal_type", "")
    for policy in _policy_entries(principal):
        policy_node_id = _add_identity_node(
            graph,
            EntityType.POLICY,
            policy["id"],
            lineage.provider,
            lineage.data_sources,
            label=policy["name"],
            policy_id=policy["id"],
            policy_name=policy["name"],
            privilege_level=policy.get("privilege_level", "unknown"),
            cloud_provider=lineage.provider,
            **_policy_document_attrs(policy),
        )
        _add_rel_edge(
            graph,
            principal_node_id,
            policy_node_id,
            RelationshipType.ATTACHED,
            {"source": "cloud_principal", "principal_type": principal_type},
        )


def _add_principal_trusts(graph: UnifiedGraph, lineage: _CloudLineage, principal: dict[str, Any], principal_node_id: str) -> None:
    principal_type = principal.get("principal_type", "")
    for trust in _trust_entries(principal):
        trust_node_id = _add_identity_node(
            graph,
            _identity_entity_type(trust["type"]),
            trust["id"],
            lineage.provider,
            lineage.data_sources,
            label=trust["name"],
            principal_id=trust["id"],
            principal_name=trust["name"],
            principal_type=trust["type"],
            cloud_provider=lineage.provider,
        )
        relationship = (
            RelationshipType.CROSS_ACCOUNT_TRUST
            if trust["relationship"] == RelationshipType.CROSS_ACCOUNT_TRUST.value
            else RelationshipType.TRUSTS
        )
        _add_rel_edge(
            graph,
            principal_node_id,
            trust_node_id,
            relationship,
            {
                "source": "cloud_principal_trust",
                "principal_type": principal_type,
                "trusted_principal_type": trust["type"],
                "source_field": trust["source_field"],
            },
        )


def _add_principal_node(graph: UnifiedGraph, lineage: _CloudLineage, principal: dict[str, Any], principal_id: str) -> str:
    principal_name = _clean_graph_part(principal.get("principal_name")) or principal_id
    principal_type = principal.get("principal_type", "")
    return _add_identity_node(
        graph,
        _identity_entity_type(principal_type),
        principal_id,
        lineage.provider,
        lineage.data_sources,
        label=principal_name,
        principal_id=principal_id,
        principal_name=principal_name,
        principal_type=principal_type,
        tenant_id=principal.get("tenant_id", ""),
        source_field=principal.get("source_field", ""),
        cloud_provider=lineage.provider,
        cloud_service=lineage.service,
        cloud_principal=principal,
    )


def _add_cloud_principal_lineage(graph: UnifiedGraph, lineage: _CloudLineage, principal: dict[str, Any], agent_id: str) -> None:
    principal_id = _clean_graph_part(principal.get("principal_id")) or _clean_graph_part(principal.get("principal_name"))
    if not principal_id:
        return
    principal_type = principal.get("principal_type", "")
    principal_node_id = _add_principal_node(graph, lineage, principal, principal_id)
    evidence = {"source": "cloud_principal", "principal_type": principal_type}
    if lineage.account_node_id:
        _add_rel_edge(graph, principal_node_id, lineage.account_node_id, RelationshipType.MEMBER_OF, dict(evidence))
    _add_rel_edge(graph, principal_node_id, lineage.resource_node_id, RelationshipType.MANAGES, dict(evidence))
    _add_rel_edge(graph, principal_node_id, lineage.resource_node_id, RelationshipType.CAN_ACCESS, dict(evidence))
    _add_principal_policies(graph, lineage, principal, principal_node_id)
    _add_principal_trusts(graph, lineage, principal, principal_node_id)
    # Direct principal → agent edge so single-hop "which principals can
    # reach this agent?" queries don't have to traverse the intermediate
    # cloud_resource node. The intermediate edges (principal → resource,
    # resource → agent) above stay so the lineage is fully reconstructable.
    # `via` records that the relationship is mediated by a cloud_resource
    # so consumers can distinguish direct ownership from cloud-mediated
    # operation when they need to.
    _add_rel_edge(
        graph,
        principal_node_id,
        agent_id,
        RelationshipType.MANAGES,
        {"source": "cloud_principal", "principal_type": principal_type, "via": lineage.resource_node_id},
    )
