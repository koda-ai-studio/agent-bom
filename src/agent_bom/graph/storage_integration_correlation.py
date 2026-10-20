"""Join Snowflake storage integrations to AWS IAM roles and S3 buckets on recorded identifiers.

A Snowflake storage integration records (``DESC INTEGRATION``) the IAM role it
assumes (``storage_aws_role_arn``), the Snowflake-owned IAM user that assumes it
(``storage_aws_iam_user_arn``), the external id it presents
(``storage_aws_external_id``) and the locations it may read
(``storage_allowed_locations``). An AWS collection records the role's ARN and
its trust policy (``trust_principals``, ``trust_external_ids``) and each
bucket's ARN. Those identifiers, from two vendors' collections, are enough to
state the cross-vendor chain without guessing:

* integration ``assumes`` role: the role ARN matches exactly, the role's trust
  names the integration's IAM user, and names its external id when one is
  recorded;
* integration ``can_access`` bucket: only through such a role, for an allowed
  ``s3://`` location whose bucket ARN is recorded on a node.

Names are never compared. Edges are ``derived`` evidence with the matched
identifiers as their basis, and re-running adds nothing.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType

SOURCE = "storage-integration-correlation"
_ROLE_ARN_PREFIX = "arn:aws:iam::"
_S3_ARN_PREFIX = "arn:aws:s3:::"


def _texts(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(part).strip() for part in value if isinstance(part, str) and part.strip()]
    return []


def _recorded_arns(node: UnifiedNode, prefix: str) -> set[str]:
    attrs = node.attributes or {}
    return {value for key in ("arn", "resource_id", "native_id") for value in _texts(attrs.get(key)) if value.startswith(prefix)}


def _bucket_arn(location: str) -> str:
    if not location.lower().startswith("s3://"):
        return ""
    bucket = location[5:].split("/", 1)[0].strip()
    return f"{_S3_ARN_PREFIX}{bucket}" if bucket else ""


def _trust_basis(integration: dict[str, Any], role: UnifiedNode) -> list[str] | None:
    attrs = role.attributes or {}
    user = str(integration.get("storage_aws_iam_user_arn") or "").strip()
    if not user or user not in _texts(attrs.get("trust_principals")):
        return None
    basis = ["storage_aws_role_arn_matches_role_arn", "role_trust_names_integration_user"]
    external_id = str(integration.get("storage_aws_external_id") or "").strip()
    if external_id:
        if external_id not in _texts(attrs.get("trust_external_ids")):
            return None
        basis.append("role_trust_names_external_id")
    return basis


def _index(nodes: Iterable[UnifiedNode], prefix: str, kind: EntityType | None = None) -> dict[str, UnifiedNode]:
    """Recorded ARN -> the one node that records it; an ARN two nodes claim is ambiguous and dropped."""
    claims: dict[str, list[UnifiedNode]] = {}
    for node in nodes:
        if kind is not None and node.entity_type != kind:
            continue
        for arn in _recorded_arns(node, prefix):
            claims.setdefault(arn, []).append(node)
    return {arn: owners[0] for arn, owners in claims.items() if len(owners) == 1}


def _add(graph: UnifiedGraph, source: UnifiedNode, target: UnifiedNode, relationship: RelationshipType, evidence: dict[str, Any]) -> bool:
    spec = relationship_spec(relationship)
    if spec is None or not spec.allows(source.entity_type, target.entity_type):
        return False
    graph.add_edge(
        UnifiedEdge(
            source=source.id,
            target=target.id,
            relationship=relationship,
            evidence={"source": SOURCE, "tier": "derived", "derived_via": "recorded_identifier_match", **evidence},
        )
    )
    return True


def correlate_storage_integrations(graph: UnifiedGraph) -> int:
    """Draw recorded-identifier joins for every storage integration; returns the edges it holds."""
    nodes = list(graph.nodes.values())
    integrations = [node for node in nodes if str((node.attributes or {}).get("storage_aws_role_arn") or "").startswith(_ROLE_ARN_PREFIX)]
    if not integrations:
        return 0
    roles = _index(nodes, _ROLE_ARN_PREFIX, EntityType.ROLE)
    buckets = _index(nodes, _S3_ARN_PREFIX)
    drawn = 0
    for integration in integrations:
        attrs = integration.attributes
        role_arn = str(attrs["storage_aws_role_arn"]).strip()
        role = roles.get(role_arn)
        basis = _trust_basis(attrs, role) if role is not None else None
        if role is None or basis is None:
            continue
        if not _add(graph, integration, role, RelationshipType.ASSUMES, {"basis": basis, "role_arn": role_arn}):
            continue
        drawn += 1
        for location in _texts(attrs.get("storage_allowed_locations")):
            bucket = buckets.get(_bucket_arn(location))
            if bucket is None or bucket.id == integration.id:
                continue
            evidence = {
                "basis": ["storage_allowed_location_names_bucket_arn", "via_assumed_role"],
                "location": location,
                "via_role": role.id,
            }
            drawn += _add(graph, integration, bucket, RelationshipType.CAN_ACCESS, evidence)
    return drawn


__all__ = ["SOURCE", "correlate_storage_integrations"]
