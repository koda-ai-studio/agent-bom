"""Resolve source-reported canonical IDs without upgrading them to execution proof.

The connection supplies cloud/account scope; the provider supplies the identifier
claim. This is an identity lookup against a named snapshot, not an authenticated
workload attestation, permission check, invocation receipt or exploit verdict.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from agent_bom.runtime.cloud_trace_claims import cloud_trace_projection


def _resource_conflicts(claims: dict[str, Any] | None, node: Any) -> bool:
    if claims is None or node is None:
        return False
    origin = node.attributes.get("cloud_origin")
    origin = origin if isinstance(origin, dict) else {}
    expected = {
        "cloud.resource_id": [origin.get("resource_id")],
        "cloud.region": [node.attributes.get("region"), node.attributes.get("location"), origin.get("location")],
    }
    return any(
        claims["attributes"].get(key) and isinstance(value, str) and value and claims["attributes"][key] != value
        for key, values in expected.items()
        for value in values
    )


def _nodes_through_aliases(store: Any, *, tenant_id: str, scan_id: str, identities: set[str]) -> dict[str, Any]:
    """An id a source minted before canonicalization merged it resolves to the canonical node."""
    resolver = getattr(store, "resolve_node_aliases", None)
    aliases: dict[str, str] = resolver(tenant_id=tenant_id, node_ids=identities) if callable(resolver) else {}
    wanted = identities | set(aliases.values())
    canonical = {node.id: node for node in store.nodes_by_ids(tenant_id=tenant_id, scan_id=scan_id, node_ids=wanted)}
    return {identity: canonical[aliases.get(identity, identity)] for identity in identities if aliases.get(identity, identity) in canonical}


def correlate_inventory_observations(
    store: Any, *, tenant_id: str, scan_id: str, observations: Sequence[Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Batch exact IDs and reject scope conflicts or a replaced snapshot."""
    if not scan_id or len(observations) > 200:
        raise ValueError("A named snapshot and bounded observation page are required")
    rows = [row for row in observations if row.get("tenant_id") == tenant_id and row.get("surface") == "imported_trace"]
    identities = {
        str(row["metadata"]["inventory_node_id"])
        for row in rows
        if isinstance(row.get("metadata"), dict)
        and isinstance(row["metadata"].get("inventory_node_id"), str)
        and 0 < len(row["metadata"]["inventory_node_id"]) <= 512
    }
    before = store.snapshot_identity(tenant_id=tenant_id, scan_id=scan_id)
    if before[0] != scan_id or not before[1]:
        return {str(row["observation_id"]): {"state": "snapshot_unavailable", "execution_proven": False} for row in rows}
    nodes = _nodes_through_aliases(store, tenant_id=tenant_id, scan_id=scan_id, identities=identities)
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        raw_metadata = row.get("metadata")
        metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
        identity = metadata.get("inventory_node_id")
        node = nodes.get(identity) if isinstance(identity, str) else None
        binding: dict[str, Any] = {"state": "unmapped", "execution_proven": False}
        result[str(row["observation_id"])] = binding
        cloud_claims = cloud_trace_projection(metadata)
        if metadata.get("cloud_trace") is not None and (
            cloud_claims is None or cloud_claims.get("scope_state") != "consistent" or _resource_conflicts(cloud_claims, node)
        ):
            binding["state"] = "scope_conflict"
            continue
        if node is None:
            continue
        if any(
            metadata.get(key) and metadata[key] != expected
            for key, expected in (("inventory_scan_id", scan_id), ("inventory_generation", before[1]))
        ):
            binding["state"] = "snapshot_conflict"
            continue
        # Every recorded alias must agree. Never let one matching field hide a
        # contradictory account or environment elsewhere on the entity.
        origin = node.attributes.get("cloud_origin")
        origin = origin if isinstance(origin, dict) else {}
        envelopes = [node.attributes, origin]
        for value in (node.attributes.get("scope"), origin.get("scope"), node.attributes.get("cloud_scope")):
            if isinstance(value, dict):
                envelopes.append(value)
        scope = {
            "cloud_provider": [node.attributes.get("cloud_provider"), node.dimensions.cloud_provider, origin.get("provider")],
            "account_id": [
                envelope.get(key) for envelope in envelopes for key in ("account_id", "cloud_account_id", "subscription_id", "project_id")
            ],
            "environment": [node.dimensions.environment, *(envelope.get("environment") for envelope in envelopes)],
        }
        for key, values in scope.items():
            recorded = {value for value in values if isinstance(value, str) and value}
            claimed = metadata.get(key)
            if not claimed or not recorded:
                binding["state"] = "scope_missing"
                break
            if recorded != {claimed}:
                binding["state"] = "scope_conflict"
                break
        else:
            binding.update(
                state="exact_identifier",
                basis="source_reported_canonical_id",
                **({"alias_of": identity} if identity != node.id else {}),
                node_id=node.id,
                scan_id=scan_id,
                snapshot_generation=before[1],
            )
    if store.snapshot_identity(tenant_id=tenant_id, scan_id=scan_id) != before:
        return {key: {"state": "snapshot_changed", "execution_proven": False} for key in result}
    return result
