"""Cloud audit-trail aggregates projected as observed principal → resource edges.

The reader (:mod:`agent_bom.cloud.audit_trail`) has already collapsed raw events
into ``(principal, resource, action)`` aggregates with ``count`` and
``last_seen``; no raw log line reaches this module. Each aggregate draws an
``INVOKED`` (a management/write action taken) or ``ACCESSED`` (a resource
reached) edge from its principal to its resource.

A principal is typed from the identity the provider recorded: an AWS assumed
role session is the role it assumed, an IAM user ARN is a user, a Google
service-account email is a service account. Only a bare name stays a user.
A resource keeps the native id the event named (ARN, ARM id, instance id) and
its account, so asset canonicalization merges it with the inventory record of
the same asset instead of leaving a second node.
"""

from __future__ import annotations

import re
from typing import Any

from agent_bom.graph.cloud_context import _add_account_resource_hierarchy, _add_identity_node, _prepare_cloud_payload
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.identity_nodes import identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part

SOURCE = "cloud-audit-trail"
_ASSUMED_ROLE = re.compile(r"^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role/([^/]+)/")
_IAM = re.compile(r"^arn:(aws[a-z-]*):iam::(\d{12}):(user|role)/(.+)$")


def principal_identity(provider: str, name: str, principal_arn: str = "", principal_type: str = "") -> tuple[EntityType, str, str]:
    """``(entity type, identity id, native arn)`` for an audit-trail principal."""
    assumed = _ASSUMED_ROLE.match(principal_arn)
    if assumed:
        partition, account, role = assumed.groups()
        arn = f"arn:{partition}:iam::{account}:role/{role}"
        return EntityType.ROLE, arn, arn
    iam = _IAM.match(principal_arn)
    if iam:
        kind = EntityType.ROLE if iam.group(3) == "role" else EntityType.USER
        return kind, principal_arn, principal_arn
    if principal_type.casefold() in {"assumedrole", "role"}:
        return EntityType.ROLE, name, ""
    if provider == "gcp" and name.casefold().endswith(".iam.gserviceaccount.com"):
        return EntityType.SERVICE_ACCOUNT, name, ""
    return EntityType.USER, name, ""


def _ensure_principal(
    graph: UnifiedGraph, rec: dict[str, Any], provider: str, data_sources: list[str], account_node_id: str, seen: set[str]
) -> str:
    name = _clean_graph_part(rec.get("principal"))
    entity_type, identity, arn = principal_identity(
        provider, name, _clean_graph_part(rec.get("principal_arn")), _clean_graph_part(rec.get("principal_type"))
    )
    node_id = identity_node_id(entity_type, provider, identity)
    if node_id in seen:
        return node_id
    seen.add(node_id)
    attrs: dict[str, Any] = {"user_name": name, "cloud_provider": provider, "source": SOURCE}
    if arn:
        attrs.update(arn=arn, account_id=arn.split(":")[4])
    if entity_type == EntityType.SERVICE_ACCOUNT:
        attrs["service_account_email"] = name
    _add_identity_node(graph, entity_type, identity, provider, data_sources, label=f"principal: {name}", **attrs)
    if account_node_id:
        _add_rel_edge(graph, account_node_id, node_id, RelationshipType.OWNS, {"source": SOURCE})
    return node_id


def _ensure_resource(
    graph: UnifiedGraph, rec: dict[str, Any], provider: str, account: str, data_sources: list[str], account_node_id: str
) -> str:
    resource = _clean_graph_part(rec.get("resource"))
    node_id = f"cloud_resource:{provider}:audit:resource:{resource}"
    if node_id in graph.nodes:
        return node_id
    attrs: dict[str, Any] = {
        "resource_name": resource,
        "resource_id": resource,
        "resource_kind": "audit-observed-resource",
        "cloud_provider": provider,
        "is_sensitive_resource": bool(rec.get("is_sensitive_resource")),
    }
    if account:
        attrs["account_id"] = account
    region = _clean_graph_part(rec.get("region"))
    if region:
        attrs["region"] = region
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.CLOUD_RESOURCE,
            label=f"resource: {resource}",
            attributes=attrs,
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider=provider, surface="cloud"),
        )
    )
    if account_node_id:
        _add_account_resource_hierarchy(graph, account_node_id, node_id, evidence={"source": SOURCE})
    return node_id


def add_cloud_audit_behavioral(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Draw one observed edge per audit aggregate. Never raises; a non-ok payload is a no-op."""
    prepared = _prepare_cloud_payload(payload, data_source, SOURCE)
    if prepared is None:
        return
    account, data_sources = prepared
    provider = _clean_graph_part(payload.get("provider")) or "cloud"
    account_node_id = ""
    if account:
        account_node_id = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            account,
            provider,
            data_sources,
            label=account or provider,
            account_id=account,
            cloud_provider=provider,
            source=SOURCE,
        )
    seen: set[str] = set()
    for rec in payload.get("behavioral_edges", []) or []:
        if not isinstance(rec, dict):
            continue
        action = _clean_graph_part(rec.get("action"))
        if not _clean_graph_part(rec.get("principal")) or not _clean_graph_part(rec.get("resource")) or not action:
            continue
        relationship = RelationshipType.INVOKED if _clean_graph_part(rec.get("relationship")) == "invoked" else RelationshipType.ACCESSED
        resource_id = _ensure_resource(graph, rec, provider, account, data_sources, account_node_id)
        _add_rel_edge(
            graph,
            _ensure_principal(graph, rec, provider, data_sources, account_node_id, seen),
            resource_id,
            relationship,
            {
                "source": SOURCE,
                "observed": True,
                "action": action,
                "observed_at": _clean_graph_part(rec.get("last_seen")),
                "observation_count": int(rec.get("count") or 0),
                "failure_count": int(rec.get("failure_count") or 0),
                "is_sensitive_resource": bool(rec.get("is_sensitive_resource")),
            },
            observed_at=_clean_graph_part(rec.get("last_seen")),
        )
