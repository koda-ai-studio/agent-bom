"""Project discovered non-human identities (NHIs) into the unified graph.

The ``agent_bom.identity`` connectors enumerate existing machine identities
(IdP service accounts, API tokens) that agent-bom did not issue. Discovered
NHIs retain their provider, scoped identity and scope metadata; verified Okta
organization membership is projected as a relationship.

Scope strings alone do not identify a tool or prove a grant to it. This overlay
therefore fails closed for tool-access relationships: it never derives a
``scoped_to`` edge from a scope name, even if it matches a tool label or ID.
Independent authorization overlays remain responsible for evidenced grants.
Re-running discovery is idempotent within a snapshot; updated observations are
projected into a new snapshot without rewriting historical evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.canonical_ids import canonical_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType
from agent_bom.identity.okta_http import org_origin
from agent_bom.identity.okta_nhi import DiscoveredNonHumanIdentity

_OVERLAY_SOURCE = "nhi-discovery"


def _correlation_attributes(identity: DiscoveredNonHumanIdentity, node_id: str) -> dict[str, str]:
    """Publish a stable key only for a validated, already normalized Okta scope."""
    if identity.provider != "okta" or not identity.source_scope:
        return {}
    try:
        if org_origin(identity.source_scope) != identity.source_scope:
            return {}
    except ValueError:
        return {}
    # The node id includes provider + org and, for NHIs, kind + native id.
    # Preserve the native id separately; display names never enter this key.
    return {"canonical_id": node_id}


def _org_membership(graph: UnifiedGraph, identity: DiscoveredNonHumanIdentity, nid: str) -> tuple[int, int]:
    added_nodes = added_edges = 0
    if identity.provider == "okta" and identity.source_scope:
        account_id = "account:okta:" + canonical_id(identity.source_scope)
        if account_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=account_id,
                    entity_type=EntityType.ACCOUNT,
                    label=identity.source_scope,
                    data_sources=[_OVERLAY_SOURCE],
                    attributes={
                        "provider": "okta",
                        "org_url": identity.source_scope,
                        **_correlation_attributes(identity, account_id),
                    },
                )
            )
            added_nodes += 1
        graph.add_edge(
            UnifiedEdge(
                source=nid,
                target=account_id,
                relationship=RelationshipType.MEMBER_OF,
                provenance={"source": _OVERLAY_SOURCE},
                evidence={"kind": "provider_inventory", "provider": "okta", "basis": "org_api_collection"},
            )
        )
        added_edges += 1
    return added_nodes, added_edges


def apply_nhi_overlay(
    graph: UnifiedGraph,
    identities: Iterable[DiscoveredNonHumanIdentity],
) -> dict[str, int]:
    """Add discovered NHIs as ``managed_identity`` nodes and organization membership in place.

    Returns a count of added nodes and edges. Idempotent: an identity whose node
    already exists is skipped. Never raises — a malformed identity is ignored.
    """
    added_nodes = 0
    added_edges = 0

    for identity in identities:
        try:
            scoped_id = (
                canonical_id(identity.source_scope, identity.identity_type, identity.identity_id)
                if identity.source_scope
                else identity.identity_id
            )
            nid = f"managed_identity:{identity.provider}:{scoped_id}"
            if nid in graph.nodes:
                continue
            graph.add_node(
                UnifiedNode(
                    id=nid,
                    entity_type=EntityType.MANAGED_IDENTITY,
                    label=identity.name or identity.identity_id,
                    data_sources=[_OVERLAY_SOURCE],
                    status=NodeStatus.ACTIVE if identity.status == "active" else NodeStatus.INACTIVE,
                    # Context node: "info" so it survives default graph filters
                    # (severity_id 0 is dropped) without outranking real findings.
                    severity="info",
                    attributes={
                        "discovered": True,
                        "provider": identity.provider,
                        "identity_id": identity.identity_id,
                        "source_scope": identity.source_scope,
                        "identity_type": identity.identity_type,
                        "status": identity.status,
                        "owner": identity.owner,
                        "created_at": identity.created_at,
                        "last_used_at": identity.last_used_at,
                        "credential_expires_at": identity.credential_expires_at,
                        "scopes": list(identity.scopes),
                        **_correlation_attributes(identity, nid),
                    },
                )
            )
            added_nodes += 1
            org_nodes, org_edges = _org_membership(graph, identity, nid)
            added_nodes += org_nodes
            added_edges += org_edges

        except Exception:  # noqa: BLE001 — never raise into the builder
            continue

    return {"nodes_added": added_nodes, "edges_added": added_edges}


def apply_nhi_overlay_from_result(graph: UnifiedGraph, result: Any) -> dict[str, int]:
    """Convenience wrapper: project the identities from an ``NHIDiscoveryResult``.

    Only the ``OK`` status contributes nodes; any other status (disabled,
    missing creds, error) is a no-op so the builder can call this unconditionally.
    """
    identities = getattr(result, "identities", None) or ()
    if getattr(result, "status", None) is not None and not getattr(result, "ok", False):
        return {"nodes_added": 0, "edges_added": 0}
    return apply_nhi_overlay(graph, identities)


def serialize_discovery_result(result: Any) -> dict[str, Any]:
    """Serialize an ``NHIDiscoveryResult`` to a JSON-safe report payload.

    Only ``identity_id`` / ``name`` / ``owner`` / timestamps / credential expiry
    / scope *references* are kept — never secret material. The payload is what
    the scan report carries under ``identity_discovery`` so the graph builder can
    rehydrate it into ``managed_identity`` nodes on a normal build.
    """
    identities = getattr(result, "identities", None) or ()
    status = getattr(result, "status", None)
    return {
        "status": getattr(status, "value", str(status) if status is not None else "ok"),
        "provider": getattr(result, "provider", None) or (identities[0].provider if identities else None),
        "coverage": list(getattr(result, "coverage", ())),
        "org_url": getattr(result, "org_url", None),
        "warnings": list(getattr(result, "warnings", ()) or ()),
        "identities": [identity.to_dict() for identity in identities],
    }


def merge_discovery_results(results: Iterable[Any]) -> dict[str, Any]:
    """Aggregate several ``NHIDiscoveryResult`` envelopes into one report payload.

    Used by the discovery entrypoint to fold multiple providers (Okta, Entra)
    into a single ``identity_discovery`` block. ``OK`` if any provider returned
    identities; otherwise carries the per-provider statuses + warnings.
    """
    providers: list[dict[str, Any]] = []
    identities: list[dict[str, Any]] = []
    warnings: list[str] = []
    any_ok = False
    for result in results:
        payload = serialize_discovery_result(result)
        providers.append(
            {
                "provider": payload.get("provider"),
                "status": payload.get("status"),
                "count": len(payload["identities"]),
                "coverage": payload["coverage"],
            }
        )
        if getattr(result, "ok", False):
            any_ok = True
            identities.extend(payload["identities"])
        warnings.extend(payload.get("warnings", []))
    return {
        "status": "partial" if any(p["status"] in {"partial", "error"} for p in providers) else "ok" if any_ok else "empty",
        "providers": providers,
        "warnings": warnings,
        "identities": identities,
    }


def apply_nhi_overlay_from_report(graph: UnifiedGraph, report_json: Any) -> dict[str, int]:
    """Project NHIs carried on a serialized scan report into the graph.

    Reads ``report_json["identity_discovery"]["identities"]`` (the payload
    produced by :func:`serialize_discovery_result` /
    :func:`merge_discovery_results`) and rehydrates each into a
    :class:`DiscoveredNonHumanIdentity` before calling :func:`apply_nhi_overlay`.
    A missing / malformed block is a no-op so the builder can call this
    unconditionally. Never raises.
    """
    block = None
    if isinstance(report_json, Mapping):
        block = report_json.get("identity_discovery")
    if not isinstance(block, Mapping):
        return {"nodes_added": 0, "edges_added": 0}
    raw_identities = block.get("identities")
    if not isinstance(raw_identities, list):
        return {"nodes_added": 0, "edges_added": 0}

    identities: list[DiscoveredNonHumanIdentity] = []
    for raw in raw_identities:
        if not isinstance(raw, Mapping):
            continue
        identity_id = str(raw.get("identity_id") or "").strip()
        if not identity_id:
            continue
        scopes_raw = raw.get("scopes")
        scopes = tuple(str(s) for s in scopes_raw if str(s).strip()) if isinstance(scopes_raw, list) else ()
        identities.append(
            DiscoveredNonHumanIdentity(
                identity_id=identity_id,
                source_scope=_opt_str(raw.get("source_scope")),
                name=str(raw.get("name") or identity_id),
                identity_type=str(raw.get("identity_type") or "service_account"),
                provider=str(raw.get("provider") or "unknown"),
                status=str(raw.get("status") or "active"),
                owner=_opt_str(raw.get("owner")),
                created_at=_opt_str(raw.get("created_at")),
                last_used_at=_opt_str(raw.get("last_used_at")),
                credential_expires_at=_opt_str(raw.get("credential_expires_at")),
                scopes=scopes,
            )
        )
    return apply_nhi_overlay(graph, identities)


def _opt_str(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


__all__ = [
    "apply_nhi_overlay",
    "apply_nhi_overlay_from_report",
    "apply_nhi_overlay_from_result",
    "merge_discovery_results",
    "serialize_discovery_result",
]
