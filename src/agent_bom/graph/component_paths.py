"""Attack paths ending at a vulnerable component (CVE or misconfiguration).

Every primary ``vulnerable_to`` edge is one occurrence. Its path walks up from
the vulnerable asset through the edges that *hold* it: dependency-class
relationships (an agent uses a server, an image depends on a package) and
containment (a container or SBOM document contains a package). The walk stops
at an entry kind (agent / user / service account) or at a node nothing else
holds. Inventory scopes (environment, account, organization, provider, fleet)
group assets without running them, so they never become a path's entry.

Each path's verdict is the occurrence's applicability (see
:mod:`agent_bom.graph.applicability`). Occurrences that are disproven or that a
VEX statement rules out produce no path, and the analysis status counts them.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.applicability import Applicability, applicability_from_payload, edge_applicability
from agent_bom.graph.asset_identity import is_compute_instance
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge, credential_edge_admits
from agent_bom.graph.edge_lookup import _rel_value
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import STRUCTURAL_EXPOSURE_SUMMARY, package_path_covers_rollup
from agent_bom.graph.relationship_specs import TraversalClass, relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType

ANALYZER = "component_paths"
MAX_HOLDER_DEPTH = 5
MAX_CHAINS_PER_OCCURRENCE = 64

_VULNERABLE_TO = RelationshipType.VULNERABLE_TO.value
_ENTRY_KINDS = frozenset({EntityType.AGENT.value, EntityType.USER.value, EntityType.SERVICE_ACCOUNT.value})
_SCOPE_KINDS = frozenset(
    {EntityType.ENVIRONMENT.value, EntityType.ACCOUNT.value, EntityType.ORG.value, EntityType.PROVIDER.value, EntityType.FLEET.value}
)
# A vulnerable workload that runs on its own is a path even when nothing holds
# it: a server, a container, or a compute instance (VM) nothing is hosted on.
_STANDALONE_HOLDERS = frozenset({EntityType.SERVER.value, EntityType.CONTAINER.value})


def _standalone(node: UnifiedNode) -> bool:
    kind = _kind(node)
    if kind == EntityType.CLOUD_RESOURCE.value:
        return is_compute_instance(node.attributes.get("resource_type"))
    return kind in _STANDALONE_HOLDERS


# Component path score (0-100): severity 0-70, KEV 15, credentials 0-10,
# tools 0-5, path signals 0-10. Known exploitation outranks one severity step.
SEVERITY_RISK_WEIGHT = 0.7
KEV_RISK_BOOST = 15.0

_UNVERIFIED_SUMMARY = (
    "Unverified structural candidate: graph topology connects the agent and vulnerable "
    "package/server, but no executable graph or symbol path has been proven."
)


def _kind(node: UnifiedNode) -> str:
    return node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)


def is_component_finding(node: UnifiedNode) -> bool:
    # Credential assessments use their own bounded, owner-scoped derivation.
    return (
        _kind(node) in {EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value}
        and node.attributes.get("rule_id") != "AGENT_REACHES_PRIVILEGED"
    )


def _holds(edge: UnifiedEdge, nodes: dict[str, UnifiedNode]) -> bool:
    """Whether ``edge.source`` holds ``edge.target`` (dependency class or containment)."""
    if not edge.traversable:
        return False
    spec = relationship_spec(_rel_value(edge))
    if spec is None or not (spec.traversal_class is TraversalClass.DEPENDENCY or spec.rel is RelationshipType.CONTAINS):
        return False
    source = nodes.get(edge.source)
    return source is not None and _kind(source) not in _SCOPE_KINDS


@dataclass
class _Counts:
    occurrences: int = 0
    paths: int = 0
    vex_excluded: int = 0
    unlikely_excluded: int = 0
    reasons: set[str] = field(default_factory=set)


def holder_chains(graph: UnifiedGraph, holder_id: str, incoming: dict[str, list[UnifiedEdge]]) -> tuple[list[list[UnifiedEdge]], bool]:
    """Every maximal holding chain ending at ``holder_id`` (edges ordered entry -> holder).

    Returns the chains and whether a depth or count budget cut the walk.
    """
    nodes = graph.nodes
    chains: list[list[UnifiedEdge]] = []
    limited = False

    def walk(node_id: str, suffix: list[UnifiedEdge], visited: frozenset[str]) -> None:
        nonlocal limited
        if len(chains) >= MAX_CHAINS_PER_OCCURRENCE:
            limited = True
            return
        node = nodes.get(node_id)
        parents = []
        if node is not None and _kind(node) not in _ENTRY_KINDS:
            parents = sorted(
                (edge for edge in incoming.get(node_id, []) if edge.source not in visited and _holds(edge, nodes)),
                key=lambda edge: (edge.source, _rel_value(edge)),
            )
        if parents and len(suffix) >= MAX_HOLDER_DEPTH:
            limited = True
            parents = []
        if not parents:
            chains.append(suffix)
            return
        seen_sources: set[str] = set()
        for edge in parents:
            if edge.source in seen_sources:
                continue
            seen_sources.add(edge.source)
            walk(edge.source, [edge, *suffix], visited | {edge.source})

    walk(holder_id, [], frozenset({holder_id}))
    return chains, limited


def occurrence_applicability(
    graph: UnifiedGraph, hops: list[str], finding: UnifiedNode, by_pair: dict[tuple[str, str], UnifiedEdge]
) -> tuple[Applicability, UnifiedEdge | None]:
    """The applicability of the occurrence a path ends at.

    ``hops`` ends with the finding. A rollup edge from a hop that names the
    holder is the most specific record of that occurrence (it is one report row
    for that server and package), so it wins over the shared holder edge.
    """
    holder = hops[-2]
    primary = by_pair.get((holder, finding.id))
    for hop in reversed(hops[:-2]):
        rollup = by_pair.get((hop, finding.id))
        by_holder = (rollup.evidence or {}).get("applicability_by_holder") if rollup is not None else None
        if isinstance(by_holder, dict) and isinstance(by_holder.get(holder), dict):
            return applicability_from_payload(by_holder[holder]), primary
    return edge_applicability(primary, finding.attributes), primary


def _occurrence_finding_ids(edge: UnifiedEdge | None, finding: UnifiedNode, hops: list[str]) -> list[str]:
    ids = (edge.evidence or {}).get("finding_ids") if edge is not None else None
    if isinstance(ids, list) and ids:
        return sorted({str(value) for value in ids if isinstance(value, str) and value})
    from agent_bom.graph.asset_entity import finding_ids_for_asset_path

    return finding_ids_for_asset_path(getattr(finding, "attributes", None), hops)


def derive_component_paths(
    graph: UnifiedGraph,
    *,
    incoming: dict[str, list[UnifiedEdge]],
    outgoing: dict[str, list[UnifiedEdge]],
    node_risk: Callable[[UnifiedNode], float],
    path_boost: Callable[[list[str]], float],
) -> list[AttackPath]:
    """One path per (entry, ..., holder, finding) chain for every applicable occurrence."""
    counts = _Counts()
    paths: list[AttackPath] = []
    seen: set[tuple[str, ...]] = set()
    nodes = graph.nodes

    for finding in nodes.values():
        if not is_component_finding(finding):
            continue
        finding_edges = [edge for edge in incoming.get(finding.id, []) if _rel_value(edge) == _VULNERABLE_TO]
        by_pair = {(edge.source, edge.target): edge for edge in finding_edges}
        for finding_edge in finding_edges:
            holder = nodes.get(finding_edge.source)
            if holder is None or package_path_covers_rollup(finding_edge, incoming):
                continue
            counts.occurrences += 1
            chains, limited = holder_chains(graph, holder.id, incoming)
            if limited:
                counts.reasons.add("holder_chain_budget")
            for chain in chains:
                hops = ([chain[0].source] if chain else []) + [edge.target for edge in chain] or [holder.id]
                if len(hops) == 1 and not _standalone(holder):
                    continue
                hops = [*hops, finding.id]
                key = tuple(hops)
                if key in seen:
                    continue
                seen.add(key)
                applicability, primary = occurrence_applicability(graph, hops, finding, by_pair)
                if applicability.vex_excluded:
                    counts.vex_excluded += 1
                    continue
                if applicability.unlikely:
                    counts.unlikely_excluded += 1
                    continue
                paths.append(
                    _component_path(graph, hops, [*chain, finding_edge], finding, applicability, primary, outgoing, node_risk, path_boost)
                )
    counts.paths = len(paths)
    graph.analysis_status[ANALYZER] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if counts.reasons else GraphAnalysisState.COMPLETE,
        reason_codes=tuple(sorted(counts.reasons)),
        limits={"holder_depth": MAX_HOLDER_DEPTH, "chains_per_occurrence": MAX_CHAINS_PER_OCCURRENCE},
        observed={
            "occurrences": counts.occurrences,
            "paths": counts.paths,
            "vex_excluded": counts.vex_excluded,
            "unlikely_excluded": counts.unlikely_excluded,
        },
    )
    return paths


def _component_path(
    graph: UnifiedGraph,
    hops: list[str],
    edges: list[UnifiedEdge],
    finding: UnifiedNode,
    applicability: Applicability,
    primary: UnifiedEdge | None,
    outgoing: dict[str, list[UnifiedEdge]],
    node_risk: Callable[[UnifiedNode], float],
    path_boost: Callable[[list[str]], float],
) -> AttackPath:
    servers = [hop for hop in hops if hop in graph.nodes and _kind(graph.nodes[hop]) == EntityType.SERVER.value]
    entry_kind = _kind(graph.nodes[hops[0]]) if hops and hops[0] in graph.nodes else ""

    def labels(rel: str) -> list[str]:
        return sorted(
            {
                graph.nodes[e.target].label
                for server in servers
                for e in outgoing.get(server, [])
                if _rel_value(e) == rel
                and e.target in graph.nodes
                and (entry_kind != EntityType.AGENT.value or credential_edge_admits(e, hops[0]))
            }
        )

    credentials, tools = labels(RelationshipType.EXPOSES_CRED.value), labels(RelationshipType.PROVIDES_TOOL.value)
    kev = KEV_RISK_BOOST if finding.attributes.get("is_kev") is True else 0.0
    # Severity contributes at most SEVERITY_RISK_WEIGHT so KEV and exposure
    # terms still separate critical/high findings instead of all saturating
    # at 100.
    risk = (
        node_risk(finding) * SEVERITY_RISK_WEIGHT
        + kev
        + min(10.0, len(credentials) * 3.0)
        + min(5.0, len(tools) * 0.5)
        + min(10.0, path_boost(hops))
    )
    # Unproven applicability is a reachability qualifier (``reachability`` /
    # ``reachability_basis``), not a reason to compress the score: compressing
    # it tied critical, KEV and low findings at the same capped value.
    summary = _UNVERIFIED_SUMMARY if applicability.verdict == "unknown" else STRUCTURAL_EXPOSURE_SUMMARY
    return AttackPath(
        source=hops[0],
        target=finding.id,
        hops=hops,
        edges=[_rel_value(edge) for edge in edges],
        composite_risk=round(min(100.0, risk), 2),
        summary=summary,
        credential_exposure=credentials,
        tool_exposure=tools,
        vuln_ids=[finding.label or finding.id],
        finding_ids=_occurrence_finding_ids(primary, finding, hops),
        reachability=applicability.verdict,
        reachability_basis=list(applicability.basis),
    )
