"""Vulnerable workload → the identity it runs as → what that identity can reach.

A CVE in a workload's image (Kubernetes) or on a VM's disk is only half of the
risk; the other half is what an attacker inherits after exploiting it. For
every workload holding at least one applicable vulnerability, this derives a
path along recorded edges only:

    workload --assumes--> service account / role
             [--inherits--> role] --can_access / has_permission--> secret / scope

The path's ``vuln_ids`` name the CVEs that make the workload the foothold, and
its reachability is the strongest applicability among them. An ``assumes``
edge a producer marked non-traversable (for example a pod with no mounted
service-account token) never starts a path.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.applicability import edge_applicability
from agent_bom.graph.asset_identity import is_compute_instance
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_lookup import _rel_value
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

E, R = EntityType, RelationshipType
MAX_TARGETS_PER_IDENTITY = 25
ANALYZER = "workload_pivot_paths"
MAX_PATHS = 500
_HOLD = frozenset({R.DEPENDS_ON.value, R.CONTAINS.value})
_REACH = frozenset({R.CAN_ACCESS.value, R.HAS_PERMISSION.value})
_IDENTITIES = frozenset({E.SERVICE_ACCOUNT, E.ROLE, E.SERVICE_PRINCIPAL, E.MANAGED_IDENTITY})
_VERDICT_ORDER = ("confirmed", "likely", "unknown")


@dataclass
class _Foothold:
    vuln_ids: set[str] = field(default_factory=set)
    worst: str = ""
    kev: bool = False
    verdicts: set[str] = field(default_factory=set)
    basis: set[str] = field(default_factory=set)


def is_workload(node: UnifiedNode) -> bool:
    if node.entity_type == E.CONTAINER:
        return node.attributes.get("container_kind") == "workload"
    return node.entity_type == E.CLOUD_RESOURCE and is_compute_instance(node.attributes.get("resource_type"))


def _content_node(node: UnifiedNode | None) -> bool:
    if node is None:
        return False
    return node.entity_type == E.PACKAGE or (node.entity_type == E.CONTAINER and node.attributes.get("container_kind") == "image")


def _record(foothold: _Foothold, edge: UnifiedEdge, vuln: UnifiedNode) -> None:
    applicability = edge_applicability(edge, vuln.attributes)
    if applicability.vex_excluded or applicability.unlikely:
        return
    foothold.vuln_ids.add(vuln.label or vuln.id)
    severity = str(vuln.severity or "").lower()
    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(foothold.worst, 0):
        foothold.worst = severity
    foothold.kev = foothold.kev or bool(vuln.attributes.get("is_kev"))
    foothold.verdicts.add(applicability.verdict)
    foothold.basis.update(applicability.basis)


def _foothold(graph: UnifiedGraph, workload_id: str, outgoing: Mapping[str, list[UnifiedEdge]]) -> _Foothold:
    """Applicable vulnerabilities in what the workload runs (image → package tree), bounded."""
    foothold = _Foothold()
    frontier, seen = [workload_id], {workload_id}
    for _depth in range(4):
        following: list[str] = []
        for node_id in frontier:
            for edge in outgoing.get(node_id, []):
                target = graph.nodes.get(edge.target)
                rel = _rel_value(edge)
                if rel == R.VULNERABLE_TO.value and target is not None and target.entity_type == E.VULNERABILITY and node_id != workload_id:
                    _record(foothold, edge, target)
                elif rel in _HOLD and edge.traversable and edge.target not in seen and _content_node(target):
                    seen.add(edge.target)
                    following.append(edge.target)
        frontier = following
    return foothold


def _reach(identity_id: str, outgoing: Mapping[str, list[UnifiedEdge]]) -> list[tuple[list[str], list[str]]]:
    tails: list[tuple[list[str], list[str]]] = []
    for edge in outgoing.get(identity_id, []):
        rel = _rel_value(edge)
        if not edge.traversable:
            continue
        if rel in _REACH:
            tails.append(([edge.target], [rel]))
        elif rel in {R.INHERITS.value, R.ASSUMES.value}:
            for hop in outgoing.get(edge.target, []):
                if hop.traversable and _rel_value(hop) in _REACH:
                    tails.append(([edge.target, hop.target], [rel, _rel_value(hop)]))
    return sorted(tails)[:MAX_TARGETS_PER_IDENTITY]


def _risk(foothold: _Foothold, target: UnifiedNode | None) -> float:
    # critical 70, high 55, medium 40, low 25, otherwise 20.
    risk = max(20.0, 15.0 * SEVERITY_RANK.get(foothold.worst, 0) - 5.0) + (15.0 if foothold.kev else 0.0)
    if target is not None and target.entity_type in {E.CREDENTIAL, E.CREDENTIAL_REF}:
        risk += 10.0
    elif target is not None and target.entity_type in {E.CLUSTER, E.ACCOUNT, E.ORG}:
        risk += 8.0
    return round(min(100.0, risk), 2)


def _path(graph: UnifiedGraph, workload: UnifiedNode, identity: str, tail: tuple[list[str], list[str]], foothold: _Foothold) -> AttackPath:
    hops = [workload.id, identity, *tail[0]]
    target = graph.nodes.get(hops[-1])
    verdict = next((v for v in _VERDICT_ORDER if v in foothold.verdicts), "unknown")
    cves = sorted(foothold.vuln_ids)
    shown = ", ".join(cves[:3]) + (f" (+{len(cves) - 3} more)" if len(cves) > 3 else "")
    identity_label = graph.nodes[identity].label if identity in graph.nodes else identity
    reach = f" and reach {target.label}" if target is not None and len(hops) > 2 else ""
    return AttackPath(
        source=workload.id,
        target=hops[-1],
        hops=hops,
        edges=[R.ASSUMES.value, *tail[1]],
        composite_risk=_risk(foothold, target),
        summary=f"Exploiting {shown} in {workload.label} lets an attacker act as {identity_label}{reach}.",
        vuln_ids=cves,
        reachability=verdict,
        reachability_basis=sorted(foothold.basis) if verdict != "unknown" else ["structural_topology_only"],
    )


def _identities(graph: UnifiedGraph, workload: UnifiedNode, outgoing: Mapping[str, list[UnifiedEdge]]) -> list[str]:
    return sorted(
        {
            edge.target
            for edge in outgoing.get(workload.id, [])
            if _rel_value(edge) == R.ASSUMES.value
            and edge.traversable
            and getattr(graph.nodes.get(edge.target), "entity_type", None) in _IDENTITIES
        }
    )


def _record_status(graph: UnifiedGraph, paths: int, footholds: int, capped: bool) -> None:
    graph.analysis_status[ANALYZER] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if capped else GraphAnalysisState.COMPLETE,
        reason_codes=("path_cap_reached",) if capped else (),
        limits={"max_paths": MAX_PATHS, "max_targets_per_identity": MAX_TARGETS_PER_IDENTITY},
        observed={"paths": paths, "vulnerable_workloads_with_identity": footholds},
    )


def workload_pivot_paths(graph: UnifiedGraph, outgoing: Mapping[str, list[UnifiedEdge]]) -> list[AttackPath]:
    paths: list[AttackPath] = []
    footholds = 0
    for workload in sorted((n for n in graph.nodes.values() if is_workload(n)), key=lambda n: n.id):
        identities = _identities(graph, workload, outgoing)
        foothold = _foothold(graph, workload.id, outgoing) if identities else None
        if foothold is None or not foothold.vuln_ids:
            continue
        footholds += 1
        for identity in identities:
            for tail in _reach(identity, outgoing) or [([], [])]:
                if len(paths) >= MAX_PATHS:
                    _record_status(graph, len(paths), footholds, capped=True)
                    return paths
                paths.append(_path(graph, workload, identity, tail, foothold))
    _record_status(graph, len(paths), footholds, capped=False)
    return paths
