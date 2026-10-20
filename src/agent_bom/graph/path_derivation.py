"""Shared topology-derived investigation paths for HTTP and MCP consumers.

This module deliberately has no FastAPI dependency. Materialized path rows
remain authoritative; callers use derivation when a snapshot has none.
"""

from __future__ import annotations

import logging

from agent_bom.cloud.normalization import coerce_truthy
from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.applicability import Applicability, edge_applicability
from agent_bom.graph.attack_path_fusion import has_sensitive_data_label
from agent_bom.graph.component_paths import derive_component_paths, occurrence_applicability
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.credential_findings import credential_finding_paths
from agent_bom.graph.edge_lookup import _build_edge_lookup as _build_edge_lookup
from agent_bom.graph.edge_lookup import _edge_relationships_for_hops as _edge_relationships_for_hops
from agent_bom.graph.edge_lookup import _EdgeLookup as _EdgeLookup
from agent_bom.graph.edge_lookup import _rel_value as _rel_value
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import rank_unique_paths, tag_path_kinds
from agent_bom.graph.path_evidence import with_technique_mappings as _with_technique_mappings
from agent_bom.graph.types import EntityType, RelationshipType

logger = logging.getLogger(__name__)

_RUNTIME_OBSERVED_RELS = frozenset(
    {
        RelationshipType.INVOKED.value,
        RelationshipType.CALLED.value,
        RelationshipType.ACCESSED.value,
        RelationshipType.ACTED_AS.value,
        RelationshipType.USED_CREDENTIAL.value,
        RelationshipType.DELEGATED_TO.value,
    }
)


def _exposed_port_detail(attrs: dict) -> str:
    """Render the internet-open ports on a node as ' on port(s) 22, 3389'."""
    ports = attrs.get("exposed_ports") or []
    if not isinstance(ports, list):
        return ""
    nums = sorted({str(p["from_port"]) for p in ports if isinstance(p, dict) and p.get("from_port") is not None})
    return f" on port(s) {', '.join(nums[:5])}" if nums else ""


def _fusion_signals_for_path(graph: UnifiedGraph, hops: list[str]) -> list[tuple[str, str, str, float]]:
    """Governance / CNAPP / runtime signals that should weight a path's rank.

    Returns ``(kind, label, detail, risk_boost)`` tuples. Inspects each hop node
    and its one-hop governance/exposure neighbours so the managed-identity,
    drift, and internet-exposure edges (added by the governance + CNAPP
    overlays) actually sharpen attack-path ranking rather than sitting inert.
    """
    signals: list[tuple[str, str, str, float]] = []
    seen_kinds: set[str] = set()

    def add(kind: str, label: str, detail: str, boost: float) -> None:
        if kind not in seen_kinds:
            seen_kinds.add(kind)
            signals.append((kind, label, detail, boost))

    for hop_id in hops:
        node = graph.nodes.get(hop_id)
        if node is None:
            continue
        attrs = node.attributes
        port_detail = _exposed_port_detail(attrs)
        # A WAF / API-gateway in front of the resource mitigates its exposure
        # (set by the CNAPP overlay). Honesty (§11): a mitigated node is NOT
        # counted as a full-weight toxic/exposed foothold, but it is NOT hidden
        # either — it surfaces as an explicitly *mitigated* signal at lower rank.
        exposure_mitigated = coerce_truthy(attrs.get("exposure_mitigated")) or coerce_truthy(attrs.get("protected_by_waf"))
        if coerce_truthy(attrs.get("toxic_exposed_vulnerable")):
            add("toxic_exposed_vulnerable", "Toxic: exposed + vulnerable", f"{node.label}: exposed{port_detail} + vulnerable.", 20.0)
        elif coerce_truthy(attrs.get("toxic_exposed_vulnerable_mitigated")):
            add(
                "toxic_exposed_vulnerable_mitigated",
                "Toxic (mitigated): exposed + vulnerable behind WAF",
                f"{node.label}: internet-exposed{port_detail} + vulnerable but fronted by a WAF/API gateway (exposure mitigated).",
                8.0,
            )
        elif coerce_truthy(attrs.get("internet_exposed")):
            if exposure_mitigated:
                add(
                    "internet_exposed_mitigated",
                    "Internet exposed (mitigated)",
                    f"{node.label} is internet-exposed{port_detail} but fronted by a WAF/API gateway (exposure mitigated).",
                    6.0,
                )
            else:
                add("internet_exposed", "Internet exposed", f"{node.label} is reachable from the public internet{port_detail}.", 15.0)
        if coerce_truthy(attrs.get("escalates_to_admin")):
            add("privilege_escalation_admin", "Admin escalation", f"{node.label} can assume an admin-privileged role.", 20.0)
        elif coerce_truthy(attrs.get("escalates_to_conditional_admin")):
            add(
                "privilege_escalation_conditional_admin",
                "Conditional admin escalation",
                f"{node.label} can assume a role with conditional admin permissions (conditions not verified).",
                18.0,
            )
        elif coerce_truthy(attrs.get("can_escalate_privilege")):
            add("privilege_escalation", "Privilege escalation", f"{node.label} can assume a role with broader effective access.", 16.0)
        # Standing admin-equivalent permissions (holds admin directly) — an
        # independent CIEM signal from the assume-chain escalation above, so it
        # is added, not chained via elif. Basis provenance stays visible.
        if coerce_truthy(attrs.get("admin_equivalent")):
            basis = attrs.get("admin_equivalence_basis")
            basis_detail = f" (basis: {basis})" if basis else ""
            add(
                "admin_equivalent",
                "Admin-equivalent identity",
                f"{node.label} holds admin-equivalent permissions{basis_detail}.",
                18.0,
            )
        if coerce_truthy(attrs.get("toxic_exposed_sensitive")):
            reach = attrs.get("sensitive_data_access_count")
            reach_detail = f", reachable by {reach} identity/tool path(s)" if isinstance(reach, int) and reach > 0 else ""
            add(
                "exposed_sensitive_data",
                "Exposed sensitive data",
                f"{node.label} holds sensitive data and is internet-exposed{reach_detail}.",
                22.0,
            )
        elif has_sensitive_data_label(attrs.get("data_sensitivity")):
            reach = attrs.get("sensitive_data_access_count")
            reach_detail = f", reachable by {reach} identity/tool path(s)" if isinstance(reach, int) and reach > 0 else ""
            add("sensitive_data", "Sensitive data", f"{node.label} holds sensitive (PII/PHI/secret) data{reach_detail}.", 8.0)
        # Activity at one hop is useful context, not proof of end-to-end
        # reachability. Blocked attempts must not become observed execution.
        hop_edges = graph.adjacency.get(hop_id, []) + graph.reverse_adjacency.get(hop_id, [])
        if any(
            _rel_value(e) in _RUNTIME_OBSERVED_RELS
            and not e.evidence.get("blocked")
            and e.evidence.get("decision") != "blocked"
            and (e.evidence.get("runtime_observed_state") or e.provenance.get("runtime_observed_state")) not in {"blocked", "not_observed"}
            for e in hop_edges
        ):
            add(
                "runtime_observed",
                "Runtime-observed",
                f"{node.label} has recorded runtime activity; end-to-end reachability is assessed separately.",
                10.0,
            )
        # One-hop governance/exposure neighbours of this node.
        for edge in graph.adjacency.get(hop_id, []):
            target = graph.nodes.get(edge.target)
            if target is None:
                continue
            rel = _rel_value(edge)
            if rel == RelationshipType.EXHIBITS_DRIFT.value:
                add("behavioral_drift", "Behavioral drift", f"{node.label} has an open drift incident.", 12.0)
            elif rel == RelationshipType.AUTHENTICATES_AS.value and not target.attributes.get("scope_bound", True):
                add("broad_identity_scope", "Unscoped identity", f"{node.label} runs as an identity with no per-tool scope.", 8.0)
            elif rel == RelationshipType.STORES.value and coerce_truthy(target.attributes.get("internet_exposed")):
                add("exposed_data_store", "Exposed data store", f"{node.label} backs an internet-exposed data store.", 14.0)
    return signals


def _node_type_value(node: UnifiedNode) -> str:
    return node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)


def _node_risk_100(node: UnifiedNode) -> float:
    """A node's risk on the canonical 0-100 scale.

    The normalisation itself lives in `graph.risk_scale` so this and
    `estate_graph._chain_risk` cannot drift apart again — they did, and the
    exposure-path queue ended up sorting two unit systems as one.
    """
    from agent_bom.graph.risk_scale import normalize_risk_to_100

    risk = normalize_risk_to_100(getattr(node, "risk_score", 0.0))
    if risk <= 0:
        # Unrated inventory nodes fall back to severity rank, which is already
        # expressed on the 0-100 scale (rank 5 -> 100).
        risk = float(SEVERITY_RANK.get(str(getattr(node, "severity", "") or "").lower(), 0) * 20)
    return max(0.0, min(100.0, risk))


_DANGEROUS_TOOL_KEYWORDS = ("shell", "exec", "run", "command", "subprocess", "filesystem", "admin", "delete", "write", "sudo", "deploy")

_MAX_GOVERNANCE_PATHS = 200


def leads_somewhere(path: AttackPath) -> bool:
    """A path crosses at least one hop to a different node.

    A single-node risk (an admin-equivalent role, a resource with stacked toxic
    factors and nothing it reaches) is a finding on that node, never a path.
    """
    return path.source != path.target and len(path.hops) >= 2


def _is_dangerous_tool(label: str) -> bool:
    low = label.lower()
    return any(keyword in low for keyword in _DANGEROUS_TOOL_KEYWORDS)


def _derived_governance_attack_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """Derive attack paths that the governance / CNAPP / effective-permission
    overlays make possible but that are not anchored on a CVE/misconfig finding.

    Surfaces five chains as first-class paths so humans and agents can
    investigate them via /v1/graph/attack-paths and the governance endpoint:

    - privilege escalation: principal --HAS_PERMISSION(assume_chain)--> resource
    - over-scoped tool access: agent --AUTHENTICATES_AS--> identity --SCOPED_TO-->
      dangerous tool (standing scope or JIT grant)
    - behavioral drift: agent --EXHIBITS_DRIFT--> drift_incident --SCOPED_TO--> tool
    - data exposure: resource --EXPOSED_TO--> internet-exposed data_store
    - broad-scope identity: agent --AUTHENTICATES_AS--> identity with no per-tool
      scope (standing access to everything it can reach), no finding anchor needed
    """
    paths: list[AttackPath] = []
    seen: set[tuple[str, str, str]] = set()

    def emit(kind: str, source: str, target: str, hops: list[str], edges: list[str], base: float, summary: str) -> None:
        key = (kind, source, target)
        if key in seen or len(paths) >= _MAX_GOVERNANCE_PATHS:
            return
        seen.add(key)
        risk = base + sum(boost for _k, _l, _d, boost in _fusion_signals_for_path(graph, hops))
        paths.append(
            AttackPath(
                source=source,
                target=target,
                hops=hops,
                edges=edges,
                composite_risk=round(min(100.0, risk), 2),
                summary=summary,
                vuln_ids=[],
            )
        )

    for edge in graph.edges:
        if not edge.traversable:
            continue
        rel = _rel_value(edge)
        src = graph.nodes.get(edge.source)
        tgt = graph.nodes.get(edge.target)
        if src is None or tgt is None:
            continue

        # Privilege escalation: effective access gained only by assuming a role.
        if rel == RelationshipType.HAS_PERMISSION.value and (edge.evidence or {}).get("access") == "assume_chain":
            exposed = coerce_truthy(tgt.attributes.get("internet_exposed"))
            emit(
                "privilege_escalation",
                src.id,
                tgt.id,
                [src.id, tgt.id],
                ["has_permission"],
                65.0 if exposed else 55.0,
                f"{src.label} reaches {tgt.label} by assuming another role" + (" (internet-exposed)." if exposed else "."),
            )
        # Data exposure: internet-exposed resource backing a data store.
        elif rel == RelationshipType.EXPOSED_TO.value and _node_type_value(tgt) == EntityType.DATA_STORE.value:
            sensitive = has_sensitive_data_label(tgt.attributes.get("data_sensitivity"))
            frameworks = tgt.attributes.get("data_regulatory_frameworks") or []
            # Name the regulation at risk when classified (PCI-DSS / HIPAA / GDPR / SOC2).
            data_descr = f"{'/'.join(frameworks)} data store" if frameworks else f"{'sensitive ' if sensitive else ''}data store"
            emit(
                "data_exposure",
                src.id,
                tgt.id,
                [src.id, tgt.id],
                ["exposed_to"],
                70.0 if sensitive else 55.0,
                f"{src.label} is internet-exposed and backs {data_descr} {tgt.label}.",
            )

    # Agent → identity → dangerous tool, and agent → drift incident → tool.
    for node in graph.nodes.values():
        ntype = _node_type_value(node)
        if ntype == EntityType.AGENT.value:
            for id_edge in graph.adjacency.get(node.id, []):
                if not id_edge.traversable:
                    continue
                if _rel_value(id_edge) == RelationshipType.AUTHENTICATES_AS.value:
                    identity = graph.nodes.get(id_edge.target)
                    if identity is None:
                        continue
                    for tool_edge in graph.adjacency.get(identity.id, []):
                        if not tool_edge.traversable:
                            continue
                        tool = graph.nodes.get(tool_edge.target)
                        if tool is None or _node_type_value(tool) != EntityType.TOOL.value or not _is_dangerous_tool(tool.label):
                            continue
                        emit(
                            "over_scoped_tool",
                            node.id,
                            tool.id,
                            [node.id, identity.id, tool.id],
                            ["authenticates_as", _rel_value(tool_edge)],
                            48.0,
                            f"{node.label} has recorded scope for high-capability tool {tool.label} through identity {identity.label}.",
                        )
                    # Broad-scope identity: standing access with no per-tool scope.
                    # This is a posture risk on its own — no vulnerability or
                    # dangerous-tool anchor required — so surface it as a path even
                    # when the identity's reachable tools are benign or not yet wired.
                    if identity.attributes.get("scope_bound") is False:
                        emit(
                            "broad_scope_identity",
                            node.id,
                            identity.id,
                            [node.id, identity.id],
                            ["authenticates_as"],
                            40.0,
                            f"{node.label} is registered to {identity.label}, an identity with no per-tool scope; "
                            "this binding does not establish request authorization or successful tool execution.",
                        )
                elif _rel_value(id_edge) == RelationshipType.EXHIBITS_DRIFT.value:
                    incident = graph.nodes.get(id_edge.target)
                    if incident is None:
                        continue
                    for tool_edge in graph.adjacency.get(incident.id, []):
                        if not tool_edge.traversable:
                            continue
                        tool = graph.nodes.get(tool_edge.target)
                        if tool is None or _node_type_value(tool) != EntityType.TOOL.value:
                            continue
                        emit(
                            "drift_to_tool",
                            node.id,
                            tool.id,
                            [node.id, incident.id, tool.id],
                            ["exhibits_drift", _rel_value(tool_edge)],
                            45.0,
                            f"{node.label} drifted to using tool {tool.label} outside its declared blueprint.",
                        )

    return paths


_TOXIC_RESOURCE_TYPES = frozenset(
    {
        EntityType.CLOUD_RESOURCE.value,
        EntityType.RESOURCE.value,
        EntityType.SERVER.value,
        EntityType.DATA_STORE.value,
    }
)

_MAX_TOXIC_PATHS = 100


def _toxic_band(factor_count: int) -> float:
    if factor_count >= 4:
        return 100.0
    if factor_count == 3:
        return 99.0
    return 82.0


def _derived_toxic_combination_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """Cloud-security crown-jewel paths: assets where multiple toxic factors stack.

    A single resource that is *internet-exposed* AND carries an *exploitable
    vulnerability* AND can *reach sensitive data* AND/or is *reachable by an
    admin-escalating identity* is the chain an attacker actually walks — and the
    one thing a security team must fix first. Each independent factor present
    raises the band; three or more is surfaced as a crown jewel at the top of
    the attack-path queue. Fuses attributes the overlays already computed (no new
    scanner input), so it surfaces wherever attack paths do — the headless
    ``/v1/graph/attack-paths`` queue for agents and the graph cockpit for humans.
    """
    vulnerable: set[str] = set()
    admin_reachable: set[str] = set()
    sensitive_neighbors: dict[str, list[str]] = {}
    for edge in graph.edges:
        rel = _rel_value(edge)
        if rel == RelationshipType.VULNERABLE_TO.value:
            vulnerability_node = graph.nodes.get(edge.target)
            if vulnerability_node is not None and edge_applicability(edge, vulnerability_node.attributes).permits_exploit_chain:
                vulnerable.add(edge.source)
        elif rel == RelationshipType.HAS_PERMISSION.value:
            principal = graph.nodes.get(edge.source)
            # A resource is admin-privilege-reachable when a principal that can
            # escalate to admin OR that already holds admin-equivalent permissions
            # has effective access to it.
            if principal is not None and (principal.attributes.get("escalates_to_admin") or principal.attributes.get("admin_equivalent")):
                admin_reachable.add(edge.target)
        elif rel in (RelationshipType.STORES.value, RelationshipType.EXPOSED_TO.value):
            store = graph.nodes.get(edge.target)
            if store is not None and has_sensitive_data_label(store.attributes.get("data_sensitivity")):
                sensitive_neighbors.setdefault(edge.source, []).append(edge.target)

    paths: list[AttackPath] = []
    for node in graph.nodes.values():
        if _node_type_value(node) not in _TOXIC_RESOURCE_TYPES or len(paths) >= _MAX_TOXIC_PATHS:
            continue
        attrs = node.attributes
        # WAF / API-gateway in front of the resource mitigates its exposure
        # (CNAPP overlay). Honesty (§11): the node still surfaces (marked
        # mitigated), but its exposure factor is not counted at full weight and
        # the composite band is capped below an unmitigated peer's.
        exposure_mitigated = coerce_truthy(attrs.get("exposure_mitigated")) or coerce_truthy(attrs.get("protected_by_waf"))
        factors: list[str] = []
        if coerce_truthy(attrs.get("internet_exposed")):
            factors.append("internet-exposed (WAF-mitigated)" if exposure_mitigated else "internet-exposed")
        if (
            node.id in vulnerable
            or coerce_truthy(attrs.get("toxic_exposed_vulnerable"))
            or coerce_truthy(attrs.get("toxic_exposed_vulnerable_mitigated"))
        ):
            factors.append("exploitable vulnerability")
        sens_ids = sensitive_neighbors.get(node.id, [])
        if has_sensitive_data_label(attrs.get("data_sensitivity")) or sens_ids:
            regs = list(attrs.get("data_regulatory_frameworks") or [])
            for sid in sens_ids:
                store = graph.nodes.get(sid)
                for code in (store.attributes.get("data_regulatory_frameworks") or []) if store else []:
                    if code not in regs:
                        regs.append(code)
            factors.append("sensitive data" + (f" ({'/'.join(regs)})" if regs else ""))
        if node.id in admin_reachable:
            factors.append("admin-privilege reachable")
        if len(factors) < 2:
            continue
        if not sens_ids:
            # Nothing reached: the stacked factors stay a toxic-combination finding on the node.
            continue
        target = sens_ids[0]
        hops = [node.id, target]
        edges = ["exposed_to"]
        base = _toxic_band(len(factors))
        if exposure_mitigated:
            # Below the unmitigated toxic band — the WAF fronts the exposure — but
            # still surfaced and marked, never dropped.
            base = min(base, 65.0)
        prefix = "Crown jewel" if len(factors) >= 3 else "Toxic combination"
        if exposure_mitigated:
            prefix += " (exposure mitigated)"
        paths.append(
            AttackPath(
                source=node.id,
                target=target,
                hops=hops,
                edges=edges,
                composite_risk=round(min(100.0, base), 2),
                summary=f"{prefix}: {node.label} stacks {len(factors)} toxic factors — " + ", ".join(factors) + ".",
                vuln_ids=[],
            )
        )
    return paths


def _cached_path_boost(graph: UnifiedGraph, hops: list[str], cache: dict[str, list[tuple[str, str, str, float]]]) -> float:
    """Path risk boost from per-hop signals; first occurrence of a kind wins, as in whole-path scoring."""
    boosts: dict[str, float] = {}
    for hop_id in hops:
        if hop_id not in cache:
            cache[hop_id] = _fusion_signals_for_path(graph, [hop_id])
        for kind, _label, _detail, boost in cache[hop_id]:
            boosts.setdefault(kind, boost)
    return sum(boosts.values())


def _hop_applicability(graph: UnifiedGraph, hops: list[str], node: UnifiedNode, occurrence_edges: dict) -> Applicability:
    """A stored path's verdict at one vulnerability hop: the occurrence edge leading into it."""
    index = hops.index(node.id)
    if index > 0 and (hops[index - 1], node.id) in occurrence_edges:
        return occurrence_applicability(graph, hops[: index + 1], node, occurrence_edges)[0]
    return edge_applicability(None, node.attributes)


def _derived_attack_paths(graph: UnifiedGraph, *, kinds: dict[int, str] | None = None) -> list[AttackPath]:
    """The snapshot's served path set: persisted fusion rows, governance / CNAPP /
    effective-permission chains, credential-owner paths and agent/server/component/
    finding chains, ranked and unique per chain (equivalent persisted rows win).
    """
    governance_paths = _derived_governance_attack_paths(graph) + _derived_toxic_combination_paths(graph)
    for path in governance_paths:
        if path.reachability == "unknown":
            path.reachability = "likely"
            path.reachability_basis = ["observed_graph_edges"]
    materialized: list[AttackPath] = []
    if graph.attack_paths:
        occurrence_edges = {
            (edge.source, edge.target): edge for edge in graph.edges if _rel_value(edge) == RelationshipType.VULNERABLE_TO.value
        }
        for path in graph.attack_paths:
            vulnerability_nodes = [
                graph.nodes[hop]
                for hop in path.hops
                if hop in graph.nodes and _node_type_value(graph.nodes[hop]) == EntityType.VULNERABILITY.value
            ]
            assessments = [_hop_applicability(graph, path.hops, node, occurrence_edges) for node in vulnerability_nodes]
            if any(item.unlikely or item.vex_excluded for item in assessments):
                continue
            if path.reachability == "unknown":
                strongest = next((item for item in assessments if item.verdict == "confirmed"), None)
                if strongest is None:
                    strongest = next((item for item in assessments if item.verdict == "likely"), None)
                if strongest is not None:
                    path.reachability = strongest.verdict
                    path.reachability_basis = list(strongest.basis)
                elif vulnerability_nodes:
                    path.reachability_basis = ["structural_topology_only"]
                    if "unverified" not in path.summary.lower():
                        path.summary = f"Unverified structural candidate. {path.summary}".strip()
            materialized.append(path)

    incoming: dict[str, list] = {}
    outgoing: dict[str, list] = {}
    for edge in graph.edges:
        incoming.setdefault(edge.target, []).append(edge)
        outgoing.setdefault(edge.source, []).append(edge)

    signal_cache: dict[str, list[tuple[str, str, str, float]]] = {}
    paths = derive_component_paths(
        graph,
        incoming=incoming,
        outgoing=outgoing,
        node_risk=_node_risk_100,
        path_boost=lambda hops: _cached_path_boost(graph, hops, signal_cache),
    )

    # Derived paths never displace an equivalent persisted/governance path.
    combined = [*materialized, *governance_paths]

    def path_key(path: AttackPath) -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
        return path.source, path.target, tuple(path.hops), tuple(path.edges)

    existing_keys = {path_key(path) for path in combined}
    credential_paths = credential_finding_paths(graph)
    for derived_path in [*credential_paths, *paths]:
        derived_path_key = path_key(derived_path)
        if derived_path_key not in existing_keys:
            combined.append(derived_path)
            existing_keys.add(derived_path_key)
    tag_path_kinds(kinds, fusion=materialized, governance=governance_paths, credential=credential_paths)
    return _with_technique_mappings(rank_unique_paths([path for path in combined if leads_somewhere(path)]), graph)
