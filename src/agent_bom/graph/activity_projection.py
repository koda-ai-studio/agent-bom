"""Recorded runtime activity, with explicit identity uncertainty and no execution claim."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from agent_bom.canonical_ids import canonical_id
from agent_bom.core.cloud_scope import assess_cloud_scope
from agent_bom.graph.activity_receipts import MAX_EVENTS, SOURCE
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.asset_identity import cloud_identity_scope, recorded_dimension
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.trace_projection import _Binder
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text

STATUS_KEY = "runtime_activity_projection"


def _text(value: object, limit: int = 512) -> str:
    return sanitize_text(value, max_len=limit) if isinstance(value, str) else ""


def _moment(value: object) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return moment if moment.tzinfo is not None else None
    except (ValueError, TypeError):
        return None


def _scoped(node: UnifiedNode, event: Mapping[str, Any]) -> bool:
    attrs = node.attributes
    assessed = cloud_identity_scope(node)
    if assessed["status"] == "unknown" and (attrs.get("account_ref") or attrs.get("source_account_id")):
        fallback_provider = str(attrs.get("cloud_provider") or attrs.get("provider") or recorded_dimension(node, "cloud_provider"))
        assessed = assess_cloud_scope(fallback_provider, attrs, str(attrs.get("account_ref") or attrs.get("source_account_id")))
    if assessed["status"] in ("conflict", "unknown"):
        return False
    origin = attrs.get("cloud_origin")
    scope = origin.get("scope", {}) if isinstance(origin, dict) else {}
    accounts = {str(attrs[key]) for key in ("account_ref", "account_id", "source_account_id", "cloud_account_id") if attrs.get(key)}
    if assessed["status"] == "scoped":
        accounts.add(str(assessed["scope_id"]))
    if isinstance(scope, dict):
        accounts.update(str(scope[key]) for key in ("account_id", "subscription_id", "project_id") if scope.get(key))
    account = event.get("account_ref") or ""
    if accounts or account:
        if not account or accounts != {account}:
            return False
    provider = (
        attrs.get("cloud_provider")
        or attrs.get("provider")
        or recorded_dimension(node, "cloud_provider")
        or (origin.get("provider") if isinstance(origin, dict) else "")
    )
    reported = event.get("provider") or ""
    if assessed["status"] == "scoped" and not reported:
        return False
    if reported:
        reported_scope = assess_cloud_scope(str(reported), attrs)
        if reported_scope["status"] == "conflict" or (not provider and reported_scope["status"] != "scoped"):
            return False
    return not provider or bool(reported and str(provider).lower() == str(reported).lower())


def _subject(graph: UnifiedGraph, binder: _Binder, event: dict[str, Any], role: str, observed: dict[str, int]) -> str:
    raw_ref = event.get(f"{role}_ref", "")
    ref = raw_ref if len(raw_ref) <= 512 and _text(raw_ref) == raw_ref else ""
    candidate = binder.node(ref)
    if role == "target" and candidate is None:
        upstream = event.get("upstream_ref", "")
        name = event.get("target_name", "")
        server = binder.node(upstream) if _text(upstream) == upstream and _text(name) == name else None
        if server is not None and server.entity_type == EntityType.SERVER and _scoped(server, event):
            candidate = binder.node(f"tool:{server.id}:{_text(event.get('target_name'))}")
    spec = relationship_spec(RelationshipType.RECORDED_ACTIVITY)
    assert spec is not None
    pair = (
        (candidate.entity_type, EntityType.RESOURCE)
        if candidate is not None and role == "agent"
        else (EntityType.RESOURCE, candidate.entity_type)
        if candidate is not None
        else None
    )
    if candidate is not None and pair is not None and spec.allows(*pair) and _scoped(candidate, event):
        observed["exact_bindings"] += 1
        return candidate.id
    if candidate is not None:
        observed["scope_rejected"] += 1
    name = _text(event.get(f"{role}_name"), 180)
    kinds = (EntityType.AGENT,) if role == "agent" else (EntityType.TOOL, EntityType.SERVER)
    candidates = {node for kind in kinds for node in binder.name_candidates(kind, name)} if name else set()
    observed["name_candidates"] += len(candidates)
    observed["shadow_bindings"] += 1
    node_id = "runtime-subject:" + canonical_id(
        SOURCE,
        graph.tenant_id,
        event.get("source"),
        event.get("surface"),
        event.get("account_ref"),
        event.get("provider"),
        event.get("session_id"),
        event["event_id"],
        role,
        raw_ref or name,
    )
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.RESOURCE,
            label=name or f"Reported {role}",
            attributes={
                "source": SOURCE,
                "identity_resolution": "unverified",
                "inventory_identity_proven": False,
                "reported_role": role,
                "candidate_count": len(candidates),
                "semantic_layer": "runtime_evidence",
            },
            data_sources=[SOURCE],
            dimensions=NodeDimensions(surface="runtime"),
        )
    )
    return node_id


def _receipt(event: dict[str, Any]) -> dict[str, str]:
    receipt = {
        key: _text(event.get(key))
        for key in (
            "event_id",
            "observed_at",
            "source",
            "surface",
            "session_id",
            "trace_id",
            "event_type",
            "verdict",
            "account_ref",
            "provider",
            "producer_assurance",
            "timestamp_basis",
            "record_digest",
        )
    }

    stamp = _moment(event["observed_at"])
    assert stamp is not None
    receipt["observed_at"] = stamp.astimezone(timezone.utc).isoformat()
    return receipt


def _valid_identity(event: object) -> bool:
    fields = (
        "tenant_id",
        "event_id",
        "source",
        "surface",
        "observed_at",
        "agent_ref",
        "target_ref",
        "upstream_ref",
        "account_ref",
        "provider",
        "session_id",
    )
    return isinstance(event, dict) and all(isinstance(event.get(key, ""), str) for key in fields)


def project_recorded_activity(graph: UnifiedGraph, payload: object, tenant_id: str) -> None:
    if not isinstance(payload, Mapping):
        return
    start, end = _moment(payload.get("window_start")), _moment(payload.get("window_end"))
    allowed_failures = {"gateway_store_unavailable", "runtime_store_unavailable", "tenant_rejected", "invalid_trace_event"}
    failures = payload.get("load_failures")
    reasons = (
        {reason for reason in failures if isinstance(reason, str) and reason in allowed_failures} if isinstance(failures, list) else set()
    )
    observed = {key: 0 for key in ("events", "edges", "exact_bindings", "shadow_bindings", "name_candidates", "scope_rejected", "rejected")}
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    events = payload.get("events")
    events = events if isinstance(events, list) else []
    if start is None or end is None or start > end:
        reasons.add("invalid_window")
        events = []
    binder, seen = _Binder(graph), set()
    for event in events[:MAX_EVENTS]:
        if not _valid_identity(event):
            observed["rejected"] += 1
            continue
        stamp = _moment(event.get("observed_at"))
        if event.get("tenant_id") != tenant_id or graph.tenant_id != tenant_id or not event.get("event_id"):
            observed["rejected"] += 1
            continue
        if stamp is None or start is None or end is None or not start <= stamp <= end:
            observed["rejected"] += 1
            continue
        event_key = (event.get("surface"), event.get("source"), event["event_id"])
        if event_key in seen:
            continue
        seen.add(event_key)
        observed["events"] += 1
        source = _subject(graph, binder, event, "agent", observed)
        target = _subject(graph, binder, event, "target", observed)
        grouped[source, target].append(_receipt(event))
    for (source, target), receipts in sorted(grouped.items()):
        receipts.sort(key=lambda row: (row["observed_at"], row["source"], row["event_id"]))
        graph.add_edge(
            UnifiedEdge(
                source=source,
                target=target,
                relationship=RelationshipType.RECORDED_ACTIVITY,
                traversable=False,
                first_seen=receipts[0]["observed_at"],
                last_seen=receipts[-1]["observed_at"],
                evidence={
                    "source": SOURCE,
                    "tier": "recorded",
                    "execution_confirmed": False,
                    "event_count": len(receipts),
                    "receipts": receipts,
                    "window_start": payload.get("window_start"),
                    "window_end": payload.get("window_end"),
                },
                provenance={"source": SOURCE, "tenant_id": tenant_id},
            )
        )
    observed["edges"] = len(grouped)
    if payload.get("load_truncated") or len(events) > MAX_EVENTS:
        reasons.add("load_cap")
    for key in ("shadow_bindings", "scope_rejected", "rejected"):
        if observed[key]:
            reasons.add(key)
    graph.analysis_status[STATUS_KEY] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if reasons else GraphAnalysisState.COMPLETE,
        reason_codes=tuple(sorted(reasons)),
        observed=observed,
        limits={"max_events": MAX_EVENTS},
    )
