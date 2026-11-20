"""Project the agent-identity governance control plane into the unified graph.

The cost/identity/drift control plane lives in dedicated stores
(``agent_identity_store``, ``drift_incident_store``) that are not part of a scan
snapshot. This overlay reads the live governance state for a tenant and emits it
as first-class graph nodes and edges, linked to the agent and tool nodes already
in the graph, so attack-path traversal can run:

    agent → managed_identity → access_grant → tool → vulnerable package
    agent ↔ drift_incident → tool

Agent bindings prefer an exact graph node ID, then an unambiguous agent label.
They describe registered identity scope, not an observed authenticated session.
Tool scopes remain context-only when conditional policy evidence is incomplete
or denies access. Unmatched governance nodes remain visible and unlinked.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.agent_identity_store import AccessContext, evaluate_conditional_access
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType

_OVERLAY_SOURCE = "governance-overlay"


def drift_incident_severity(drift_score: float) -> str:
    """Severity of an open behavioural-drift incident from its drift score."""
    return "high" if drift_score >= 0.66 else "medium" if drift_score >= 0.33 else "low"


def _label_index(graph: UnifiedGraph, entity_type: EntityType) -> dict[str, list[str]]:
    index: dict[str, list[str]] = defaultdict(list)
    for node in graph.nodes.values():
        if node.entity_type == entity_type:
            index[node.label.strip().lower()].append(node.id)
    return index


def _gnode(node_id: str, entity_type: EntityType, label: str, *, seen: tuple[str, str], **kw: Any) -> UnifiedNode:
    attributes = kw.pop("attributes", {})
    # Governance context nodes carry an "info" severity so they survive default
    # graph queries (severity_id 0 / unknown is dropped by some filters) while
    # never outranking real findings. Callers (e.g. drift) override this.
    kw.setdefault("severity", "info")
    return UnifiedNode(
        id=node_id,
        entity_type=entity_type,
        label=label,
        data_sources=[_OVERLAY_SOURCE],
        attributes=attributes,
        first_seen=seen[0],
        last_seen=seen[1],
        **kw,
    )


def _gedge(source: str, target: str, rel: RelationshipType, *, seen: tuple[str, str], **kw: Any) -> UnifiedEdge:
    return UnifiedEdge(
        source=source,
        target=target,
        relationship=rel,
        provenance={"source": _OVERLAY_SOURCE},
        first_seen=seen[0],
        last_seen=seen[1],
        **kw,
    )


def _record_seen(record: Any, first_field: str, last_field: str, fallback: str) -> tuple[str, str]:
    """When the record was written, never when it is read."""
    first = getattr(record, first_field, "") or fallback
    return first, getattr(record, last_field, "") or first


def _project_blueprints(
    graph: UnifiedGraph,
    tenant_id: str,
    blueprint_store: Any,
    agents_by_label: dict[str, list[str]],
    add_node: Callable[[UnifiedNode], None],
    add_edge: Callable[[UnifiedEdge], None],
) -> tuple[dict[str, str], dict[str, str]]:
    """Emit the stored, approved blueprints; return their node ids by seed and by id.

    The snapshot references a durable blueprint entity (by id) rather than a code
    constant, so drift incidents tie back to the persisted blueprint they derive
    from. Best-effort: a store failure degrades to no blueprint nodes.
    """
    by_seed: dict[str, str] = {}
    by_id: dict[str, str] = {}
    try:
        if blueprint_store is None:
            from agent_bom.api.blueprint_store import get_blueprint_store

            blueprint_store = get_blueprint_store()
        blueprints = blueprint_store.list_blueprints(tenant_id, limit=200).blueprints
    except Exception:  # noqa: BLE001
        blueprints = []
    for blueprint in blueprints:
        bnid = f"blueprint:{blueprint.blueprint_id}"
        by_id[blueprint.blueprint_id] = bnid
        if blueprint.seeded_from:
            by_seed[blueprint.seeded_from] = bnid
        blueprint_seen = _record_seen(blueprint, "created_at", "updated_at", graph.created_at)
        add_node(
            _gnode(
                bnid,
                EntityType.BLUEPRINT,
                blueprint.name or blueprint.blueprint_id,
                seen=blueprint_seen,
                attributes={
                    "blueprint_id": blueprint.blueprint_id,
                    "owner": blueprint.owner,
                    "approval_status": blueprint.approval_status,
                    "current_version": blueprint.current_version,
                    "latest_version": blueprint.latest_version,
                    "seeded_from": blueprint.seeded_from,
                },
            )
        )
        for agent_id in agents_by_label.get(blueprint.owner.strip().lower(), []):
            add_edge(_gedge(bnid, agent_id, RelationshipType.GOVERNS, seen=blueprint_seen))
    return by_seed, by_id


_STORE_LIMIT = 500
_CONDITION_FIELDS = (
    "allowed_environments",
    "allowed_hours_utc",
    "allowed_weekdays",
    "allowed_source_cidrs",
    "allowed_devices",
    "allowed_groups",
    "allowed_clients",
    "require_device_managed",
    "require_device_compliant",
    "require_device_disk_encrypted",
)


def _bounded_read(read: Callable[[], list], reasons: set[str], limit_reason: str, unavailable_reason: str) -> list:
    """One store read; a full page or a failure is recorded as a limitation reason."""
    try:
        records = read()
    except Exception:  # noqa: BLE001
        reasons.add(unavailable_reason)
        return []
    if len(records) >= _STORE_LIMIT:
        reasons.add(limit_reason)
    return records


class _Overlay:
    """Mutable projection state shared by the per-record-type passes."""

    def __init__(self, graph: UnifiedGraph, policies: list, reasons: set[str], moment: datetime) -> None:
        self.graph = graph
        self.policies = policies
        self.reasons = reasons
        self.moment = moment
        self.agents_by_label = _label_index(graph, EntityType.AGENT)
        self.tools_by_label = _label_index(graph, EntityType.TOOL)
        self.added_nodes = 0
        self.added_edges = 0
        self.identity_node_by_id: dict[str, str] = {}
        self.live_identities: dict[str, Any] = {}

    def seen(self, record: Any, first_field: str, last_field: str) -> tuple[str, str]:
        return _record_seen(record, first_field, last_field, self.graph.created_at)

    def add_node(self, node: UnifiedNode) -> None:
        if node.id not in self.graph.nodes:
            self.graph.add_node(node)
            self.added_nodes += 1

    def add_edge(self, edge: UnifiedEdge) -> None:
        self.graph.add_edge(edge)
        self.added_edges += 1

    def link_tool(self, source_id: str, tool_name: str, rel: RelationshipType, **kw: Any) -> None:
        for tool_id in self.tools_by_label.get(tool_name.strip().lower(), []):
            self.add_edge(_gedge(source_id, tool_id, rel, **kw))

    def scoped_tool(self, source_id: str, tool_name: str, identity: Any, **kw: Any) -> None:
        ctx = AccessContext(identity_id=identity.identity_id, agent_id=identity.agent_id, tool_name=tool_name, at=self.moment)
        applicable = [p for p in self.policies if p.status == "active" and p.applies_to(ctx)]
        conditional = [p for p in applicable if any(getattr(p, field, None) for field in _CONDITION_FIELDS)]
        unconditional = [p for p in applicable if p not in conditional]
        allowed, _reason, policy_id = evaluate_conditional_access(unconditional, ctx)
        state = "recorded_scope"
        if not allowed:
            state = "explicit_deny"
            self.reasons.add("explicit_policy_denies")
        elif conditional:
            state = "context_required"
            self.reasons.add("conditional_access_context_required")
        elif {"conditional_policies_unavailable", "conditional_policy_limit"} & self.reasons:
            state = "policy_evidence_unavailable"
        evidence = {**kw.pop("evidence", {}), "authorization_state": state}
        if policy_id:
            evidence["policy_ids"] = [policy_id]
        elif conditional:
            evidence["policy_ids"] = sorted(p.policy_id for p in conditional)
            evidence["required_context"] = sorted({field for p in conditional for field in _CONDITION_FIELDS if getattr(p, field, None)})
        self.link_tool(source_id, tool_name, RelationshipType.SCOPED_TO, traversable=state == "recorded_scope", evidence=evidence, **kw)


def _identity_is_live(overlay: _Overlay, identity: Any) -> bool:
    try:
        live: bool = identity.is_live(at=overlay.moment)
        return live
    except (TypeError, ValueError):
        overlay.reasons.add("invalid_identity_validity")
        return False


def _identity_node(nid: str, identity: Any, live: bool, identity_seen: tuple[str, str]) -> UnifiedNode:
    return _gnode(
        nid,
        EntityType.MANAGED_IDENTITY,
        identity.agent_id or identity.identity_id,
        seen=identity_seen,
        status=NodeStatus.ACTIVE if live else NodeStatus.INACTIVE,
        attributes={
            "identity_id": identity.identity_id,
            "agent_id": identity.agent_id,
            "role": identity.role,
            "status": identity.status,
            "expires_at": identity.expires_at,
            "is_live": live,
            "allowed_tools": list(identity.allowed_tools),
            "scope_bound": bool(identity.allowed_tools),
            # Surface the accountability + usage fields the NHI governance
            # evaluator reads so ownership/dormancy verdicts reflect the
            # real identity record instead of defaulting every identity to
            # orphaned + never-observed.
            "owner": getattr(identity, "owner", "") or "",
            "owner_type": getattr(identity, "owner_type", "") or "",
            "last_used_at": getattr(identity, "last_used_at", "") or "",
        },
    )


def _bind_identity_agent(overlay: _Overlay, nid: str, identity: Any, identity_seen: tuple[str, str]) -> None:
    """Link the identity to its agent by exact node id, else by one unambiguous label."""
    exact_agent = overlay.graph.nodes.get(identity.agent_id)
    exact_match = exact_agent is not None and exact_agent.entity_type == EntityType.AGENT
    matches = [identity.agent_id] if exact_match else overlay.agents_by_label.get((identity.agent_id or "").strip().lower(), [])
    if len(matches) == 1:
        overlay.add_edge(
            _gedge(
                matches[0],
                nid,
                RelationshipType.AUTHENTICATES_AS,
                seen=identity_seen,
                valid_from=identity.issued_at,
                valid_to=identity.expires_at or None,
                evidence={
                    "identity_match_basis": "exact_node_id" if exact_match else "unique_agent_label",
                    "runtime_observed_state": "not_observed",
                },
            )
        )
    elif len(matches) > 1:
        overlay.reasons.add("ambiguous_agent_identity")


def _project_identities(overlay: _Overlay, identities: list) -> None:
    """Managed identities plus their standing per-tool scope."""
    for identity in identities:
        nid = f"managed_identity:{identity.identity_id}"
        overlay.identity_node_by_id[identity.identity_id] = nid
        live = _identity_is_live(overlay, identity)
        if live:
            overlay.live_identities[identity.identity_id] = identity
        identity_seen = overlay.seen(identity, "issued_at", "last_used_at")
        overlay.add_node(_identity_node(nid, identity, live, identity_seen))
        if not live:
            overlay.reasons.add("inactive_identity")
            continue
        _bind_identity_agent(overlay, nid, identity, identity_seen)
        for tool_name in identity.allowed_tools:
            if tool_name != "*":
                overlay.scoped_tool(
                    nid,
                    tool_name,
                    identity,
                    seen=identity_seen,
                    weight=3.0,
                    valid_from=identity.issued_at,
                    valid_to=identity.expires_at or None,
                )


def _project_jit_grants(overlay: _Overlay, grants: list) -> None:
    """JIT grants: time-bound access to a tool, attached to a live identity."""
    for grant in grants:
        if grant.status != "active":
            continue
        gid = f"access_grant:{grant.grant_id}"
        grant_seen = overlay.seen(grant, "requested_at", "approved_at")
        overlay.add_node(
            _gnode(
                gid,
                EntityType.ACCESS_GRANT,
                f"JIT {grant.tool_name}",
                seen=grant_seen,
                status=NodeStatus.ACTIVE,
                attributes={
                    "grant_id": grant.grant_id,
                    "identity_id": grant.identity_id,
                    "tool": grant.tool_name,
                    "approved_by": grant.approved_by,
                    "expires_at": grant.expires_at,
                    "ticket_id": grant.ticket_id,
                },
            )
        )
        identity_node = overlay.identity_node_by_id.get(grant.identity_id)
        identity = overlay.live_identities.get(grant.identity_id)
        if not (identity_node and identity):
            overlay.reasons.add("jit_identity_unavailable")
            continue
        overlay.add_edge(
            _gedge(identity_node, gid, RelationshipType.ATTACHED, seen=grant_seen, valid_from=grant.starts_at, valid_to=grant.expires_at)
        )
        overlay.scoped_tool(
            gid,
            grant.tool_name,
            identity,
            seen=grant_seen,
            weight=4.0,
            valid_from=grant.starts_at,
            valid_to=grant.expires_at,
            evidence={"kind": "jit_grant", "ticket_id": grant.ticket_id},
        )


def _project_policies(overlay: _Overlay) -> None:
    """Conditional-access policies and what they govern."""
    for policy in overlay.policies:
        pid = f"access_policy:{policy.policy_id}"
        policy_seen = overlay.seen(policy, "created_at", "updated_at")
        overlay.add_node(
            _gnode(
                pid,
                EntityType.ACCESS_POLICY,
                policy.name,
                seen=policy_seen,
                attributes={
                    "policy_id": policy.policy_id,
                    "effect": policy.effect,
                    "priority": policy.priority,
                    "allowed_environments": list(policy.allowed_environments),
                    "allowed_source_cidrs": list(policy.allowed_source_cidrs),
                },
            )
        )
        for agent_name in policy.agent_ids:
            for agent_id in overlay.agents_by_label.get(agent_name.strip().lower(), []):
                overlay.add_edge(_gedge(pid, agent_id, RelationshipType.GOVERNS, seen=policy_seen))
        for identity_id in policy.identity_ids:
            node = overlay.identity_node_by_id.get(identity_id)
            if node:
                overlay.add_edge(_gedge(pid, node, RelationshipType.GOVERNS, seen=policy_seen))
        for tool_name in policy.tools:
            if tool_name != "*":
                overlay.link_tool(pid, tool_name, RelationshipType.GOVERNS, seen=policy_seen)


def _drift_node(did: str, incident: Any, score: float, incident_seen: tuple[str, str]) -> UnifiedNode:
    return _gnode(
        did,
        EntityType.DRIFT_INCIDENT,
        f"drift: {incident.blueprint_id}",
        seen=incident_seen,
        status=NodeStatus.VULNERABLE,
        risk_score=round(min(10.0, score * 10.0), 2),
        severity=drift_incident_severity(score),
        attributes={
            "incident_id": incident.incident_id,
            "blueprint_id": incident.blueprint_id,
            "drift_score": score,
            "violation_count": incident.violation_count,
            "occurrences": incident.occurrences,
            "status": incident.status,
        },
    )


def _project_drift(overlay: _Overlay, incidents: list, blueprints: tuple[dict[str, str], dict[str, str]]) -> None:
    """Open drift incidents, tied to their agents, blueprint and violating tools."""
    blueprint_node_by_seed, blueprint_node_by_id = blueprints
    for incident in incidents:
        did = f"drift_incident:{incident.incident_id}"
        score = float(getattr(incident, "drift_score", 0.0) or 0.0)
        incident_seen = overlay.seen(incident, "first_detected_at", "last_detected_at")
        overlay.add_node(_drift_node(did, incident, score, incident_seen))
        for agent_id in overlay.agents_by_label.get((incident.blueprint_id or "").strip().lower(), []):
            overlay.add_edge(
                _gedge(agent_id, did, RelationshipType.EXHIBITS_DRIFT, seen=incident_seen, direction="bidirectional", weight=5.0)
            )
        # Tie the incident to the persisted blueprint it drifted from (matched by
        # the archetype the blueprint was seeded from, else a direct id match) so
        # the graph references the stored blueprint, not just the code constant.
        blueprint_node = blueprint_node_by_seed.get(incident.blueprint_id) or blueprint_node_by_id.get(incident.blueprint_id)
        if blueprint_node:
            overlay.add_edge(_gedge(blueprint_node, did, RelationshipType.GOVERNS, seen=incident_seen, weight=5.0))
        for violation in getattr(incident, "top_violations", []) or []:
            tool_name = str(violation.get("tool_name", "")) if isinstance(violation, dict) else ""
            if tool_name:
                overlay.link_tool(
                    did, tool_name, RelationshipType.SCOPED_TO, seen=incident_seen, weight=4.0, evidence={"kind": "drift_violation"}
                )


def apply_governance_overlay(
    graph: UnifiedGraph,
    *,
    tenant_id: str,
    identity_store: Any = None,
    drift_store: Any = None,
    blueprint_store: Any = None,
) -> dict[str, int]:
    """Add managed-identity / JIT / conditional-policy / drift nodes+edges in place.

    Returns a count of added nodes and edges. Reads from the global stores when
    ``identity_store`` / ``drift_store`` / ``blueprint_store`` are not supplied.
    Never raises: a store failure degrades to a partial overlay.

    All three stores are injectable for the same reason: a caller that supplies
    empty stores must get an empty overlay. ``blueprint_store`` used to be read
    from the process singleton with no injection point, so a test passing empty
    identity and drift stores still picked up whatever blueprints another test
    had seeded — an "empty stores" case that was not actually empty.
    """
    if identity_store is None:
        from agent_bom.api.agent_identity_store import get_agent_identity_store

        identity_store = get_agent_identity_store()
    if drift_store is None:
        from agent_bom.api.drift_incident_store import get_drift_incident_store

        drift_store = get_drift_incident_store()

    moment = datetime.now(timezone.utc)
    reasons: set[str] = set()
    policies = _bounded_read(
        lambda: identity_store.list_conditional_policies(tenant_id, include_disabled=False, limit=_STORE_LIMIT),
        reasons,
        "conditional_policy_limit",
        "conditional_policies_unavailable",
    )
    overlay = _Overlay(graph, policies, reasons, moment)
    identities = _bounded_read(
        lambda: identity_store.list(tenant_id, include_inactive=False, limit=_STORE_LIMIT),
        reasons,
        "identity_limit",
        "identities_unavailable",
    )
    _project_identities(overlay, identities)
    grants = _bounded_read(
        lambda: identity_store.list_jit_grants(tenant_id, include_inactive=False, limit=_STORE_LIMIT),
        reasons,
        "jit_grant_limit",
        "jit_grants_unavailable",
    )
    _project_jit_grants(overlay, grants)
    _project_policies(overlay)
    blueprints = _project_blueprints(graph, tenant_id, blueprint_store, overlay.agents_by_label, overlay.add_node, overlay.add_edge)
    try:
        incidents = drift_store.list(tenant_id, include_resolved=False, limit=_STORE_LIMIT)
    except Exception:  # noqa: BLE001
        incidents = []
    _project_drift(overlay, incidents, blueprints)

    graph.analysis_status["governance_overlay"] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if reasons else GraphAnalysisState.COMPLETE,
        reason_codes=tuple(sorted(reasons)),
        limits={"max_identities": _STORE_LIMIT, "max_jit_grants": _STORE_LIMIT, "max_conditional_policies": _STORE_LIMIT},
        observed={
            "identities": len(identities),
            "live_identities": len(overlay.live_identities),
            "jit_grants": len(grants),
            "conditional_policies": len(policies),
        },
    )
    return {"nodes_added": overlay.added_nodes, "edges_added": overlay.added_edges}
