"""Location boundaries used by exact-identity correlation and evidence readers."""

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from agent_bom.graph.asset_identity import IdentityKey, family_of, recorded_dimension, strong_key_components, strong_keys
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

CORRELATION_IDENTITY_VERSION = "scoped-identity.v5"
IDENTIFIER_NAMESPACES = {"resource_arn": "arn", "provider_id": "resource_id", "stable_id": "canonical_id"}


def merged_identity_version(receipts: Iterable[object]) -> str:
    """Reprocessing a legacy join cannot repair its missing source scope."""
    return (
        CORRELATION_IDENTITY_VERSION
        if all(
            not receipt or isinstance(receipt, dict) and receipt.get("identity_version") == CORRELATION_IDENTITY_VERSION
            for receipt in receipts
        )
        else "legacy"
    )


def exact_identity_scope(node: UnifiedNode, *, basis: str, namespace: str, value: str) -> dict[str, str]:
    """Use recorded scope; preserve conflicts rather than guessing a location."""
    keys = ["cloud_provider", "cloud_account_id", "account_id", "tenant_id", "subscription_id", "project_id"]
    dimensions = []
    arn = value.split(":", 5) if namespace == "arn" else []
    qualified_arn = (
        len(arn) == 6
        and arn[0] == "arn"
        and bool(arn[1] and arn[2] and arn[5])
        and (bool(arn[3] and len(arn[4]) == 12 and arn[4].isascii() and arn[4].isdigit()) or (arn[2] == "s3" and not arn[3] and not arn[4]))
    )
    if basis in {"cloud_resource_id", "provider_identity_id", "runtime_stable_id"}:
        dimensions.append("cloud_provider")
        if not qualified_arn:
            keys.extend(["cluster_id", "cluster_arn", "region", "namespace"])
    if basis == "runtime_stable_id":
        keys.extend(["runtime_host_id", "environment"])
        dimensions.append("environment")
    scope = {key: str(node.attributes.get(key) or "").strip() for key in keys if str(node.attributes.get(key) or "").strip()}
    for key in dimensions:
        value = recorded_dimension(node, key)
        if value:
            if key in scope and scope[key] != value:
                scope[f"conflicting_dimension_{key}"] = value
            scope.setdefault(key, value)
    # A fully-qualified ARN already carries its location. Collection metadata
    # cannot split it, but a contradictory recorded region is not a safe join.
    recorded_region = str(node.attributes.get("region") or "").strip()
    if qualified_arn and arn[3] and recorded_region and recorded_region != arn[3]:
        scope["conflicting_arn_region"] = recorded_region
    return scope


def container_occurrence(node: UnifiedNode) -> dict[str, object] | None:
    """Return recorded deployment identity; image digests never locate containers."""
    attrs = node.attributes
    scope = {
        key: str(attrs.get(key) or "").strip()
        for key in (
            "cloud_provider",
            "cloud_account_id",
            "account_id",
            "tenant_id",
            "subscription_id",
            "project_id",
            "cluster_id",
            "cluster_arn",
            "runtime_host_id",
            "environment",
        )
        if str(attrs.get(key) or "").strip()
    }
    for key in ("cloud_provider", "environment"):
        dimension = recorded_dimension(node, key)
        if dimension:
            if key in scope and scope[key] != dimension:
                scope[f"conflicting_dimension_{key}"] = dimension
            scope.setdefault(key, dimension)
    located = bool(scope.get("cloud_provider")) and any(
        scope.get(key)
        for key in ("cluster_id", "cluster_arn", "runtime_host_id", "cloud_account_id", "account_id", "subscription_id", "project_id")
    )
    uid_key = "runtime_uid" if attrs.get("runtime_uid") else "container_id"
    uid = str(attrs.get(uid_key) or "").strip()
    if not uid and attrs.get("kubernetes_uid") and attrs.get("container_name") and (scope.get("cluster_id") or scope.get("cluster_arn")):
        uid_key = "kubernetes_container"
        uid = f"{attrs['kubernetes_uid']}:{attrs['container_name']}"
    if uid and located:
        return {"scope": scope, "uid_kind": uid_key, "runtime_uid": uid}
    return None


def identity_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def identity_entity_value(node: UnifiedNode) -> str:
    return node.entity_type.value if isinstance(node.entity_type, EntityType) else str(node.entity_type)


def snapshot_scoped_identity(node: UnifiedNode, *, scan_id: str) -> tuple[str, str, str]:
    entity_type = identity_entity_value(node)
    return entity_type, f"snapshot:{scan_id}:{node.canonical_id}", "snapshot_scoped_missing_exact_identity"


def exact_attribute_identity(
    node: UnifiedNode,
    *,
    keys: Sequence[str],
    basis: str,
) -> tuple[str, str, str] | None:
    key = next((key for key in keys if str(node.attributes.get(key) or "").strip()), "")
    value = str(node.attributes.get(key) or "").strip()
    if not value:
        return None
    namespace = IDENTIFIER_NAMESPACES.get(key, key)
    scope = exact_identity_scope(node, basis=basis, namespace=namespace, value=value)
    return identity_entity_value(node), identity_digest({"scope": scope, "namespace": namespace, "value": value}), basis


def runtime_stable_identity(node: UnifiedNode, *, scan_id: str) -> tuple[str, str, str]:
    """Resolve runtime identity with the same scope rules used by correlation."""
    if str(node.attributes.get("cloud_provider") or node.dimensions.cloud_provider).lower() == "snowflake":
        return snapshot_scoped_identity(node, scan_id=scan_id)
    exact = exact_attribute_identity(node, keys=("runtime_id", "stable_id", "canonical_id"), basis="runtime_stable_id")
    return exact or snapshot_scoped_identity(node, scan_id=scan_id)


def _strong_key_text(key: IdentityKey) -> str:
    return f"{key.provider or 'native'}:{key.namespace}:{key.value}"


def strong_identity(node: UnifiedNode, entity_type: str) -> tuple[str, str, str] | None:
    """The key asset canonicalization merges on, so a snapshot merge and one build agree."""
    strong = strong_keys(node)
    return (entity_type, _strong_key_text(strong[0]), f"strong_key:{strong[0].namespace}") if strong else None


def strong_member_keys(node: UnifiedNode) -> tuple[str, list[IdentityKey]]:
    return family_of(node), strong_keys(node)


def strong_member_identities(
    members: Mapping[tuple[str, str], tuple[str, Sequence[IdentityKey]]],
) -> tuple[dict[tuple[str, str], str], int]:
    """Final identity of every strong-keyed ``(scan_id, node_id)`` and the conflict count.

    Runs the same conflict-guarded grouping as one build's canonicalization over
    every snapshot at once, so a strong-key conflict keeps observations apart on
    both paths instead of joining them on a shared best key.
    """
    components = strong_key_components({f"{scan}\x00{node}": value for (scan, node), value in members.items()})
    identities = components.identities()
    resolved: dict[tuple[str, str], str] = {}
    for scan, node in members:
        root = components.find(f"{scan}\x00{node}")
        if root not in identities:
            continue
        key, unique = identities[root]
        resolved[(scan, node)] = _strong_key_text(key) if unique else f"{_strong_key_text(key)}#{identity_digest(root)[7:23]}"
    return resolved, components.conflicts


def container_identity(node: UnifiedNode, *, scan_id: str) -> tuple[str, str, str]:
    """A located runtime occurrence, else the workload's strong key, else snapshot-scoped."""
    entity_type = identity_entity_value(node)
    occurrence = container_occurrence(node)
    if occurrence:
        return entity_type, identity_digest(occurrence), "runtime_occurrence"
    strong = strong_identity(node, entity_type) if family_of(node) == "workload" else None
    if strong:
        return strong
    scoped_type, scoped_id, _basis = snapshot_scoped_identity(node, scan_id=scan_id)
    return scoped_type, scoped_id, "snapshot_scoped_runtime_occurrence"


def timestamp_instant(value: str) -> datetime:
    """Parse one evidence timestamp into a comparable UTC instant."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("correlation timestamps must be valid ISO-8601 values") from exc
    if parsed.tzinfo is None:
        raise ValueError("correlation timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _timestamp_sort_key(value: str) -> tuple[datetime, str]:
    return timestamp_instant(value), value


def oldest_timestamp(values: Sequence[str]) -> str:
    return min(values, key=_timestamp_sort_key)


def newest_timestamp(values: Sequence[str]) -> str:
    return max(values, key=_timestamp_sort_key)
