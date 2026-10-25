"""UnifiedGraph — the single graph container with traversal, filtering, and views."""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.analysis import GraphAnalysisStatus, analysis_status_map_from_dict, analysis_status_map_to_dict
from agent_bom.graph.bottleneck import BottleneckAnalysis, compute_bottlenecks
from agent_bom.graph.edge import UnifiedEdge, merge_edge_evidence
from agent_bom.graph.integration_contract import GRAPH_ENVELOPE_VERSION, validate_graph_version
from agent_bom.graph.legend import ENTITY_LEGEND as ENTITY_LEGEND
from agent_bom.graph.legend import RELATIONSHIP_LEGEND as RELATIONSHIP_LEGEND
from agent_bom.graph.legend import LegendEntry as LegendEntry
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.rekey import rekey_in_memory
from agent_bom.graph.relationship_contract import ContractRejections, admit_edge, merge_edge_provenance
from agent_bom.graph.severity_floor import FINDING_ENTITY_TYPES, counts_as_finding
from agent_bom.graph.technique_mapping import TechniqueMapping as TechniqueMapping
from agent_bom.graph.technique_mapping import technique_mappings_from_json as technique_mappings_from_json
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType
from agent_bom.graph.util import _now_iso
from agent_bom.graph.view_filters import GraphFilterOptions as GraphFilterOptions


@dataclass(slots=True)
class AttackPath:
    """Precomputed attack path between two nodes."""

    source: str
    target: str
    hops: list[str] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)
    composite_risk: float = 0.0
    summary: str = ""
    credential_exposure: list[str] = field(default_factory=list)
    tool_exposure: list[str] = field(default_factory=list)
    vuln_ids: list[str] = field(default_factory=list)
    # Stable Finding.id values that anchor this path (preferred over CVE labels
    # in vuln_ids). Additive — empty on legacy rows; API may recompute from
    # vulnerability node attributes.finding_id.
    finding_ids: list[str] = field(default_factory=list)
    # Whether the path is executable evidence (confirmed/likely), explicitly
    # disproven (unlikely), or structural investigation context (unknown).
    reachability: str = "unknown"
    reachability_basis: list[str] = field(default_factory=list)
    # One immutable evidence receipt per directed hop. Additive and empty on
    # legacy snapshots; correlation/runtime surfaces populate this before a
    # path is presented as verified.
    hop_evidence: list[dict[str, Any]] = field(default_factory=list)
    # Snapshot-wide/path-analysis completeness. Kept separate from hop receipts
    # so bounded analysis cannot be mistaken for an exhaustive clean result.
    analysis: dict[str, Any] = field(default_factory=dict)
    # Typed MITRE ATT&CK / ATLAS techniques mapped from this path's observed
    # evidence, ordered by hop. Potential/mapped techniques for the kill-chain
    # sequence — never a claim of observed attacker activity.
    technique_mappings: list[TechniqueMapping] = field(default_factory=list)

    def mitre_technique_ids(self) -> list[str]:
        """Deduped, sorted technique IDs mapped across all hops (convenience)."""
        return sorted({m.technique_id for m in self.technique_mappings})

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "hops": self.hops,
            "edges": self.edges,
            "composite_risk": self.composite_risk,
            "summary": self.summary,
            "credential_exposure": self.credential_exposure,
            "tool_exposure": self.tool_exposure,
            "vuln_ids": self.vuln_ids,
            "finding_ids": self.finding_ids,
            "reachability": self.reachability,
            "reachability_basis": self.reachability_basis,
            "hop_evidence": self.hop_evidence,
            "analysis": self.analysis,
            "technique_mappings": [m.to_dict() for m in self.technique_mappings],
            "mitre_technique_ids": self.mitre_technique_ids(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackPath:
        return cls(
            source=data["source"],
            target=data["target"],
            hops=data.get("hops", []),
            edges=data.get("edges", []),
            composite_risk=data.get("composite_risk", 0.0),
            summary=data.get("summary", ""),
            credential_exposure=data.get("credential_exposure", []),
            tool_exposure=data.get("tool_exposure", []),
            vuln_ids=data.get("vuln_ids", []),
            finding_ids=list(data.get("finding_ids") or []),
            reachability=str(data.get("reachability") or "unknown"),
            reachability_basis=[str(item) for item in data.get("reachability_basis") or []],
            hop_evidence=[dict(item) for item in data.get("hop_evidence") or [] if isinstance(item, dict)],
            analysis=dict(data.get("analysis") or {}),
            technique_mappings=[TechniqueMapping.from_dict(m) for m in data.get("technique_mappings", [])],
        )


@dataclass(slots=True)
class Campaign:
    """A deterministic cluster of fused attack paths converging on one crown jewel.

    Campaigns are the large-estate decision surface: instead of thousands of raw
    paths, an operator sees a handful of prioritized campaigns, each grouping every
    kill-chain that terminates at the same crown-jewel data store. Identity is
    derived from ``tenant_id`` + the jewel's canonical id, so the *same estate*
    yields the *same* ``campaign_id`` across runs and backends.
    """

    campaign_id: str
    crown_jewel: str
    crown_jewel_label: str
    partition: str
    owner: str
    business_impact: str
    exploitability: float | None
    expected_risk_reduction: float | None
    path_count: int
    top_path_summary: str
    cross_partition: bool
    evidence: list[str] = field(default_factory=list)
    member_paths: list[str] = field(default_factory=list)
    priority_score: float | None = None
    priority_method: str | None = None
    exploitability_evidence: dict[str, Any] = field(default_factory=dict)
    expected_risk_reduction_evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("exploitability", "expected_risk_reduction"):
            value = getattr(self, name)
            evidence = getattr(self, f"{name}_evidence")
            refs = evidence.get("evidence_refs") if isinstance(evidence, dict) else None
            supported = (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                and value >= 0
                and isinstance(evidence, dict)
                and evidence.get("status") == "complete"
                and evidence.get("basis") in {"observed", "runtime_observed", "inferred", "modeled"}
                and isinstance(refs, list)
                and bool(refs)
                and all(isinstance(ref, str) and ref.strip() for ref in refs)
            )
            if not supported:
                setattr(self, name, None)
                setattr(
                    self, f"{name}_evidence", {"status": "unavailable", "evidence_refs": [], "reason_codes": ["assessment_not_recorded"]}
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "crown_jewel": self.crown_jewel,
            "crown_jewel_label": self.crown_jewel_label,
            "partition": self.partition,
            "owner": self.owner,
            "business_impact": self.business_impact,
            "exploitability": self.exploitability,
            "expected_risk_reduction": self.expected_risk_reduction,
            "path_count": self.path_count,
            "top_path_summary": self.top_path_summary,
            "cross_partition": self.cross_partition,
            "evidence": self.evidence,
            "member_paths": self.member_paths,
            "priority_score": self.priority_score,
            "priority_method": self.priority_method,
            "exploitability_evidence": self.exploitability_evidence,
            "expected_risk_reduction_evidence": self.expected_risk_reduction_evidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Campaign:
        return cls(
            campaign_id=str(data["campaign_id"]),
            crown_jewel=str(data.get("crown_jewel", "")),
            crown_jewel_label=str(data.get("crown_jewel_label", "")),
            partition=str(data.get("partition", "")),
            owner=str(data.get("owner", "")),
            business_impact=str(data.get("business_impact", "")),
            exploitability=data.get("exploitability"),
            expected_risk_reduction=data.get("expected_risk_reduction"),
            exploitability_evidence=data.get("exploitability_evidence", {}),
            expected_risk_reduction_evidence=data.get("expected_risk_reduction_evidence", {}),
            priority_score=data.get("priority_score"),
            priority_method=data.get("priority_method"),
            path_count=int(data.get("path_count", 0)),
            top_path_summary=str(data.get("top_path_summary", "")),
            cross_partition=bool(data.get("cross_partition", False)),
            evidence=list(data.get("evidence", [])),
            member_paths=list(data.get("member_paths", [])),
        )


@dataclass(slots=True)
class InteractionRisk:
    """Cross-agent interaction risk pattern."""

    pattern: str
    agents: list[str]
    risk_score: float
    description: str
    owasp_agentic_tag: Optional[str] = None
    # Graph node ids of ``agents``; names alone are ambiguous across scopes.
    agent_node_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "agents": self.agents,
            "agent_node_ids": self.agent_node_ids,
            "risk_score": self.risk_score,
            "description": self.description,
            "owasp_agentic_tag": self.owasp_agentic_tag,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InteractionRisk:
        return cls(
            pattern=data["pattern"],
            agents=data.get("agents", []),
            risk_score=data.get("risk_score", 0.0),
            description=data.get("description", ""),
            owasp_agentic_tag=data.get("owasp_agentic_tag"),
            agent_node_ids=[str(item) for item in data.get("agent_node_ids") or []],
        )


def resolve_node_budget(budget: int | None) -> int | None:
    """Normalize a node budget; non-positive means unbounded.

    Callers that need a whole graph to be correct — snapshot diff, compare,
    anything computing removals — must be able to opt out, because a truncated
    graph would read as deletions that never happened.
    """
    if budget is None or budget <= 0:
        return None
    return budget


def apply_node_budget(graph: "UnifiedGraph", budget: int | None) -> "UnifiedGraph":
    """Trim *graph* in place to the highest-risk ``budget`` nodes.

    For backends that cannot push a limit into their query, this keeps the
    bounded-and-declared contract uniform: the same completeness descriptor is
    populated whether the cap was applied in SQL or afterwards. Edges whose
    endpoints were dropped go too, so no edge dangles.
    """
    resolved = resolve_node_budget(budget)
    total = len(graph.nodes)
    if resolved is None or total <= resolved:
        graph.completeness = GraphCompleteness(node_budget=resolved, total_nodes=total, returned_nodes=total)
        return graph

    ranked = sorted(graph.nodes.values(), key=lambda n: (-(n.risk_score or 0.0), n.id))
    keep = {node.id for node in ranked[:resolved]}
    graph.nodes = {node_id: node for node_id, node in graph.nodes.items() if node_id in keep}

    surviving = [edge for edge in graph.edges if edge.source in keep and edge.target in keep]
    graph.edges = []
    graph.adjacency = defaultdict(list)
    graph.reverse_adjacency = defaultdict(list)
    graph._edge_keys = set()
    for edge in surviving:
        graph.add_edge(edge)
    graph.completeness = GraphCompleteness(
        truncated=True,
        node_budget=resolved,
        total_nodes=total,
        returned_nodes=len(graph.nodes),
        reason="node_budget",
    )
    return graph


@dataclass(slots=True)
class GraphCompleteness:
    """Whether a loaded graph is the whole snapshot, and what was left out.

    A bounded load is fine; a *silent* one is not. Without this a caller cannot
    tell an empty blast radius from a trimmed one, which is the difference
    between "nothing reaches this" and "we stopped looking".
    """

    truncated: bool = False
    node_budget: int | None = None
    total_nodes: int = 0
    returned_nodes: int = 0
    reason: str = ""
    depth_limited: bool = False
    """The walk stopped at ``max_depth`` with reachable neighbours still unwalked.

    Distinct from ``truncated``, which is a *budget* overrun: widening the node
    budget recovers different nodes than widening the depth. Both mean the
    result is not exhaustive, so both surface as ``truncated`` in ``to_dict``;
    the reason names which one. Set only when the frontier was demonstrably
    non-empty, so a walk that really did exhaust the graph inside its depth cap
    still reports ``complete``.
    """

    @property
    def omitted_nodes(self) -> int:
        return max(0, self.total_nodes - self.returned_nodes)

    def to_dict(self) -> dict[str, Any]:
        """Serialize through the shared graph-completeness contract.

        The API already has one shape for "is this response exhaustive"; this
        must not become a second one that clients have to branch on.
        """
        from agent_bom.graph.completeness import graph_completeness

        return graph_completeness(
            returned=self.returned_nodes,
            total=self.total_nodes,
            truncated=self.truncated or self.depth_limited,
            reason=self.reason or ("depth_limit" if self.depth_limited else ""),
        )


@dataclass
class UnifiedGraph:
    """The canonical graph structure for agent-bom.

    Direction-aware: only bidirectional edges get reverse adjacency entries.
    """

    nodes: dict[str, UnifiedNode] = field(default_factory=dict)
    edges: list[UnifiedEdge] = field(default_factory=list)
    adjacency: dict[str, list[UnifiedEdge]] = field(default_factory=lambda: defaultdict(list))
    reverse_adjacency: dict[str, list[UnifiedEdge]] = field(default_factory=lambda: defaultdict(list))
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set, repr=False)
    contract_rejections: ContractRejections = field(default_factory=ContractRejections, repr=False)

    attack_paths: list[AttackPath] = field(default_factory=list)
    attack_campaigns: list[Campaign] = field(default_factory=list)
    interaction_risks: list[InteractionRisk] = field(default_factory=list)
    analysis_status: dict[str, GraphAnalysisStatus] = field(default_factory=dict)

    # NHI-governance findings and the trace-projection outcome (shadow entities)
    # are held opaquely so callers (CLI scan_cmd + API pipeline) can route them
    # into the unified finding stream without the container importing findings.
    nhi_governance_findings: list[Any] = field(default_factory=list)
    runtime_trace_projection: Any = None

    scan_id: str = ""
    tenant_id: str = ""
    created_at: str = ""
    completeness: "GraphCompleteness" = field(default_factory=lambda: GraphCompleteness())

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now_iso()

    # ── Mutation ─────────────────────────────────────────────────────────

    def add_node(self, node: UnifiedNode) -> None:
        """Add or merge a node.  Cross-source metadata is unioned."""
        existing = self.nodes.get(node.id)
        if existing:
            existing.last_seen = node.last_seen or _now_iso()
            existing.merge_attributes_and_risk(node)
            # Severity: higher wins
            if SEVERITY_RANK.get(node.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = node.severity
                existing.severity_id = node.severity_id
            # Union data_sources
            existing_sources = set(existing.data_sources)
            for ds in node.data_sources:
                if ds not in existing_sources:
                    existing.data_sources.append(ds)
                    existing_sources.add(ds)
            # Union compliance_tags
            existing_tags = set(existing.compliance_tags)
            for tag in node.compliance_tags:
                if tag not in existing_tags:
                    existing.compliance_tags.append(tag)
                    existing_tags.add(tag)
            # Merge dimensions (non-empty wins)
            existing.dimensions = existing.dimensions.merge(node.dimensions)
            return
        self.nodes[node.id] = node

    def add_edge(self, edge: UnifiedEdge) -> None:
        self._add_edge(edge, admit=True)

    def rekey_nodes(self, mapping: dict[str, str]) -> int:
        """Collapse node ids onto canonical ids, re-pointing every edge; returns dropped self-edges."""
        return rekey_in_memory(self, mapping)

    def add_stored_edge(self, edge: UnifiedEdge) -> None:
        """Add a persisted edge as stored: the relationship contract is a write-time check."""
        self._add_edge(edge, admit=False)

    def _add_edge(self, edge: UnifiedEdge, *, admit: bool) -> None:
        """Add an edge with O(1) deduplication; reverse adjacency only for bidirectional edges.

        When the (source, target, relationship) triple already exists, the new
        edge's evidence and provenance are **merged into** the kept edge (the
        builder adds one logical edge from several paths, e.g. package-path then
        blast-radius). New edges pass the relationship contract first.
        """
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
        key = (edge.source, edge.target, rel)
        if key in self._edge_keys:
            for stored in self.adjacency.get(edge.source, []):
                if stored.target == edge.target and stored.relationship == edge.relationship:
                    merge_edge_evidence(stored.evidence, edge.evidence)
                    merge_edge_provenance(stored, edge)
                    break
            return
        if admit and not admit_edge(self.nodes, edge, self.contract_rejections):
            return
        self._edge_keys.add(key)
        self.edges.append(edge)
        self.adjacency[edge.source].append(edge)
        self.reverse_adjacency[edge.target].append(edge)  # "what points at this node?" — always populated
        # Forward adjacency for bidirectional edges (traversal both ways)
        if edge.is_bidirectional:
            reverse = UnifiedEdge(
                source=edge.target,
                target=edge.source,
                relationship=edge.relationship,
                direction=edge.direction,
                weight=edge.weight,
                traversable=edge.traversable,
                first_seen=edge.first_seen,
                last_seen=edge.last_seen,
                valid_from=edge.valid_from,
                valid_to=edge.valid_to,
                source_scan_id=edge.source_scan_id,
                source_run_id=edge.source_run_id,
                evidence=edge.evidence,
                confidence=edge.confidence,
                provenance=edge.provenance,
                activity_id=edge.activity_id,
            )
            self.adjacency[edge.target].append(reverse)
            self.reverse_adjacency[edge.source].append(reverse)

    # ── Query ────────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[UnifiedNode]:
        return self.nodes.get(node_id)

    def nodes_by_type(self, entity_type: EntityType) -> list[UnifiedNode]:
        return [n for n in self.nodes.values() if n.entity_type == entity_type]

    def iter_nodes_by_type(self, entity_type: EntityType) -> Iterator[UnifiedNode]:
        """Stream nodes of one type for read-only scans (mutations need ``get_node``)."""
        return (n for n in self.nodes.values() if n.entity_type == entity_type)

    def edges_from(self, node_id: str) -> list[UnifiedEdge]:
        return self.adjacency.get(node_id, [])

    def neighbors(self, node_id: str) -> list[str]:
        return [e.target for e in self.adjacency.get(node_id, [])]

    def has_node(self, node_id: str) -> bool:
        return node_id in self.nodes

    def has_edge(self, source: str, target: str) -> bool:
        return any(e.target == target for e in self.adjacency.get(source, []))

    # ── Reverse queries ("what points at X?") ────────────────────────────

    def edges_to(self, node_id: str) -> list[UnifiedEdge]:
        """All edges whose target is this node (O(1) via reverse index)."""
        return self.reverse_adjacency.get(node_id, [])

    def sources_of(self, node_id: str) -> list[str]:
        """All node IDs that have an edge pointing at this node."""
        return [e.source for e in self.reverse_adjacency.get(node_id, [])]

    def impact_of(self, node_id: str, max_depth: int = 4) -> dict:
        """Blast radius: who can act on *node_id*, under the stores' reach policy.

        Walks inbound over the dependency, authority, exposure, runtime and
        derived classes only (see ``graph.reach_view``); a finding root enters
        through the assets it names. Containment, correlation and sibling
        findings are never "affected".
        """
        from agent_bom.graph.reach_memory import in_memory_impact

        return in_memory_impact(self, node_id, max_depth)

    def search_nodes(self, query: str, limit: int = 50) -> list[UnifiedNode]:
        """Search nodes by label, attributes, or compliance tags.

        Case-insensitive substring match across label, entity_type,
        severity, data_sources, compliance_tags, and string attribute values.
        """
        q = query.lower()
        results: list[UnifiedNode] = []
        for node in self.nodes.values():
            if len(results) >= limit:
                break
            if q in node.label.lower():
                results.append(node)
                continue
            if q in (node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type):
                results.append(node)
                continue
            if q in node.severity.lower():
                results.append(node)
                continue
            if any(q in ds.lower() for ds in node.data_sources):
                results.append(node)
                continue
            if any(q in tag.lower() for tag in node.compliance_tags):
                results.append(node)
                continue
            if any(q in str(v).lower() for v in node.attributes.values() if isinstance(v, str)):
                results.append(node)
                continue
        return results

    # ── Filtering ────────────────────────────────────────────────────────

    def filter_nodes(
        self,
        *,
        entity_types: set[EntityType] | None = None,
        min_severity: str = "",
        status: NodeStatus | None = None,
        data_source: str = "",
        dimension_filters: dict[str, str] | None = None,
    ) -> list[UnifiedNode]:
        result: list[UnifiedNode] = []
        min_rank = SEVERITY_RANK.get(min_severity, 0)
        for node in self.nodes.values():
            if entity_types and node.entity_type not in entity_types:
                continue
            if min_severity and SEVERITY_RANK.get(node.severity, 0) < min_rank:
                continue
            if status and node.status != status:
                continue
            if data_source and data_source not in node.data_sources:
                continue
            if dimension_filters:
                dims = node.dimensions.to_dict()
                if not all(dims.get(k) == v for k, v in dimension_filters.items()):
                    continue
            result.append(node)
        return result

    def filter_edges(
        self,
        *,
        relationships: set[RelationshipType] | None = None,
        traversable_only: bool = False,
        min_weight: float = 0.0,
        static_only: bool = False,
        dynamic_only: bool = False,
    ) -> list[UnifiedEdge]:
        result: list[UnifiedEdge] = []
        for edge in self.edges:
            if relationships and edge.relationship not in relationships:
                continue
            if traversable_only and not edge.traversable:
                continue
            if edge.weight < min_weight:
                continue
            if static_only and edge.relationship in _DYNAMIC_RELS:
                continue
            if dynamic_only and edge.relationship not in _DYNAMIC_RELS:
                continue
            result.append(edge)
        return result

    # ── Traversal (direction-aware) ──────────────────────────────────────

    def bfs(
        self,
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> list[list[str]]:
        """BFS from source, respecting edge direction via adjacency map."""
        if source not in self.nodes:
            return []
        paths: list[list[str]] = []
        queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
        visited: set[str] = {source}
        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth + 1:
                continue
            if len(path) > 1:
                paths.append(path)
            for edge in self.adjacency.get(current, []):
                if traversable_only and not edge.traversable:
                    continue
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge.target]))
        return paths

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        """BFS shortest path, direction-aware."""
        if source not in self.nodes or target not in self.nodes:
            return None
        if source == target:
            return [source]
        queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
        visited: set[str] = {source}
        while queue:
            current, path = queue.popleft()
            for edge in self.adjacency.get(current, []):
                if edge.target == target:
                    return path + [target]
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge.target]))
        return None

    def reachable_from(
        self,
        source: str,
        max_depth: int = 6,
        *,
        traversable_only: bool = False,
        include_source: bool = True,
    ) -> set[str]:
        """All node IDs reachable from source, direction-aware."""
        if source not in self.nodes:
            return set()
        visited: set[str] = {source}
        queue: deque[tuple[str, int]] = deque([(source, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self.adjacency.get(current, []):
                if traversable_only and not edge.traversable:
                    continue
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, depth + 1))
        if not include_source:
            visited.discard(source)
        return visited

    def traverse_subgraph(
        self,
        roots: list[str],
        *,
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        max_edges: int = 10_000,
        deadline_monotonic: float | None = None,
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[UnifiedGraph, dict[str, int], bool]:
        """Traverse the graph from one or more roots and return a bounded subgraph.

        ``direction`` controls whether traversal follows outgoing edges,
        incoming edges, or both. The returned edges always preserve their
        original orientation in the canonical graph.
        """
        sub = UnifiedGraph(
            scan_id=self.scan_id,
            tenant_id=self.tenant_id,
            created_at=self.created_at,
            analysis_status=dict(self.analysis_status),
        )
        if not roots:
            return self._inherit_completeness(sub), {}, False

        visited: set[str] = set()
        depth_by_node: dict[str, int] = {}
        traversed_edges: dict[tuple[str, str, str], UnifiedEdge] = {}
        queue: deque[tuple[str, int]] = deque()

        for root in roots:
            if root not in self.nodes:
                continue
            queue.append((root, 0))
            if include_roots:
                visited.add(root)
            depth_by_node[root] = 0

        truncated = False
        depth_limited = False
        edge_count = 0

        def _edge_allowed(edge: UnifiedEdge) -> bool:
            if relationship_types and edge.relationship not in relationship_types:
                return False
            if traversable_only and not edge.traversable:
                return False
            if static_only and edge.relationship in _DYNAMIC_RELS:
                return False
            if dynamic_only and edge.relationship not in _DYNAMIC_RELS:
                return False
            return True

        while queue:
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                truncated = True
                break
            current, depth = queue.popleft()

            candidates: list[tuple[str, UnifiedEdge]] = []
            if direction in {"forward", "both"}:
                candidates.extend((edge.target, edge) for edge in self.adjacency.get(current, []))
            if direction in {"reverse", "both"}:
                candidates.extend((edge.source, edge) for edge in self.reverse_adjacency.get(current, []))

            if depth >= max_depth:
                # The walk stops here. Say so only if it actually left something
                # behind: a frontier node whose neighbours were all visited
                # anyway cost the caller nothing, and flagging it would make
                # `truncated` meaningless on every bounded query.
                if not depth_limited and any(
                    neighbor not in visited and neighbor in self.nodes and _edge_allowed(edge) for neighbor, edge in candidates
                ):
                    depth_limited = True
                continue

            for neighbor, edge in candidates:
                if not _edge_allowed(edge):
                    continue
                edge_count += 1
                if edge_count > max_edges:
                    truncated = True
                    break

                rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
                traversed_edges[(edge.source, edge.target, rel)] = edge

                if neighbor in visited:
                    continue
                if len(visited) >= max_nodes:
                    truncated = True
                    continue
                visited.add(neighbor)
                depth_by_node[neighbor] = depth + 1
                queue.append((neighbor, depth + 1))
            if truncated and (edge_count > max_edges or (deadline_monotonic is not None and time.monotonic() >= deadline_monotonic)):
                break

        if include_roots:
            visited.update(root for root in roots if root in self.nodes)

        for node_id in visited:
            node = self.nodes.get(node_id)
            if node:
                sub.add_node(node)

        for edge in traversed_edges.values():
            if edge.source in sub.nodes and edge.target in sub.nodes:
                sub.add_edge(edge)

        self._inherit_completeness(
            sub,
            truncated=truncated,
            reason="traversal_budget",
            node_budget=max_nodes if truncated else None,
            depth_limited=depth_limited,
        )
        return sub, depth_by_node, truncated

    # ── Centrality ───────────────────────────────────────────────────────

    def degree_centrality(self) -> dict[str, float]:
        """Distinct neighbours in EITHER direction, normalised.

        Out-degree alone scored a node that 50,000 identities point at as 0 —
        the single most-referenced node in an estate read as unconnected.
        Counting distinct neighbours (rather than edges) keeps a bidirectional
        edge, which is indexed both ways, from counting twice.
        """
        if not self.nodes:
            return {}
        max_possible = max(len(self.nodes) - 1, 1)

        def degree(node_id: str) -> int:
            out = {edge.target for edge in self.adjacency.get(node_id, ())}
            incoming = {edge.source for edge in self.reverse_adjacency.get(node_id, ())}
            return len(out | incoming)

        return {nid: degree(nid) / max_possible for nid in self.nodes}

    def bottleneck_analysis(self, top_n: int = 5) -> BottleneckAnalysis:
        """Ranked bottlenecks with the source sample they were derived from."""
        return compute_bottlenecks(
            list(self.nodes),
            lambda node_id: (edge.target for edge in self.adjacency.get(node_id, ())),
            top_n=top_n,
        )

    def bottleneck_nodes(self, top_n: int = 5) -> list[tuple[str, float]]:
        """Ranked bottlenecks only. Prefer :meth:`bottleneck_analysis` — any
        surface that PRESENTS this ranking has to disclose that it is a sample."""
        return self.bottleneck_analysis(top_n).nodes

    # ── Stats ────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        severity_counts: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            et = node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type
            type_counts[et] += 1
            if node.severity and counts_as_finding(entity_type=et, node_id=node.id, attributes=node.attributes):
                severity_counts[node.severity] += 1
        rel_counts: dict[str, int] = defaultdict(int)
        for edge in self.edges:
            rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else edge.relationship
            rel_counts[rel] += 1
        return {
            "total_nodes": len(self.nodes),
            # Estate size BEFORE any load-time bound. `total_nodes` counts what
            # this graph holds; without the source total beside it a bounded
            # load reads as the whole estate, and contradicts the `completeness`
            # block shipped in the same response.
            "total_nodes_source": max(self.completeness.total_nodes, len(self.nodes)),
            "total_edges": len(self.edges),
            "node_types": dict(type_counts),
            "severity_counts": dict(severity_counts),
            "relationship_types": dict(rel_counts),
            "attack_path_count": len(self.attack_paths),
            "attack_campaign_count": len(self.attack_campaigns),
            "interaction_risk_count": len(self.interaction_risks),
            "max_attack_path_risk": max((p.composite_risk for p in self.attack_paths), default=0.0),
            "highest_interaction_risk": max((r.risk_score for r in self.interaction_risks), default=0.0),
            "analysis_status": analysis_status_map_to_dict(self.analysis_status),
        }

    # ── Serialisation ────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": GRAPH_ENVELOPE_VERSION,
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "attack_campaigns": [c.to_dict() for c in self.attack_campaigns],
            "interaction_risks": [r.to_dict() for r in self.interaction_risks],
            "analysis_status": analysis_status_map_to_dict(self.analysis_status),
            "stats": self.stats(),
            # Whether this payload is the whole snapshot or a bounded slice of
            # it. A budget-trimmed graph that serializes without this reads to
            # every consumer as the complete estate — an empty blast radius
            # becomes indistinguishable from one we stopped walking.
            "completeness": self.completeness.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedGraph:
        validate_graph_version(data)
        graph = cls(
            scan_id=data.get("scan_id", ""),
            tenant_id=data.get("tenant_id", ""),
            created_at=data.get("created_at", ""),
            analysis_status=analysis_status_map_from_dict(data.get("analysis_status", {})),
        )
        completeness = data.get("completeness")
        if isinstance(completeness, dict):
            graph.completeness = GraphCompleteness(
                truncated=bool(completeness.get("truncated", False)),
                total_nodes=int(completeness.get("total", 0) or 0),
                returned_nodes=int(completeness.get("returned", 0) or 0),
                reason=str(completeness.get("reason", "") or ""),
            )
        for nd in data.get("nodes", []):
            graph.add_node(UnifiedNode.from_dict(nd))
        for ed in data.get("edges", []):
            graph.add_stored_edge(UnifiedEdge.from_dict(ed))
        for pd in data.get("attack_paths", []):
            graph.attack_paths.append(AttackPath.from_dict(pd))
        for cd in data.get("attack_campaigns", []):
            graph.attack_campaigns.append(Campaign.from_dict(cd))
        for rd in data.get("interaction_risks", []):
            graph.interaction_risks.append(InteractionRisk.from_dict(rd))
        return graph

    # ── OCSF export (findings only) ──────────────────────────────────────

    def to_ocsf_events(self, product_version: str = "0.0.0", *, enrich_neighbors: bool = True) -> list[dict[str, Any]]:
        """Export finding-type nodes as OCSF events.

        When ``enrich_neighbors=True`` (default), each event includes a
        ``graph_context`` block with affected agents, servers, credentials,
        and attack path depth — so SOC analysts see blast radius in the SIEM
        without querying the graph API separately.
        """
        events = []
        for node in self.nodes.values():
            if node.entity_type not in FINDING_ENTITY_TYPES:
                continue
            event = node.to_ocsf_event(product_version)
            if enrich_neighbors:
                sources = self.sources_of(node.id)
                impact = self.impact_of(node.id)
                source_nodes = [self.nodes[s] for s in sources if s in self.nodes]
                event["graph_context"] = {
                    "affected_agents": [n.label for n in source_nodes if n.entity_type == EntityType.AGENT],
                    "affected_servers": [n.label for n in source_nodes if n.entity_type == EntityType.SERVER],
                    "affected_packages": [n.label for n in source_nodes if n.entity_type == EntityType.PACKAGE],
                    "exposed_credentials": [n.label for n in source_nodes if n.entity_type == EntityType.CREDENTIAL],
                    "blast_radius": impact["affected_count"],
                    "blast_by_type": impact["affected_by_type"],
                }
            events.append(event)
        return events

    # ── Graph views (subgraphs) ──────────────────────────────────────────

    def inventory_view(self) -> UnifiedGraph:
        sub = self._subgraph(
            node_filter=lambda n: (
                n.status == NodeStatus.ACTIVE
                and n.entity_type
                not in (
                    EntityType.VULNERABILITY,
                    EntityType.MISCONFIGURATION,
                )
            ),
            edge_filter=lambda e: (
                e.relationship
                in (
                    RelationshipType.HOSTS,
                    RelationshipType.HOSTED_ON,
                    RelationshipType.USES,
                    RelationshipType.DEPENDS_ON,
                    RelationshipType.PROVIDES_TOOL,
                    RelationshipType.EXPOSES_CRED,
                    RelationshipType.REACHES_TOOL,
                    RelationshipType.SERVES_MODEL,
                    RelationshipType.CONTAINS,
                )
            ),
        )
        return self._inherit_completeness(sub)

    def attack_path_view(self) -> UnifiedGraph:
        return self._inherit_completeness(self._subgraph(edge_filter=lambda e: e.traversable))

    def lateral_movement_view(self) -> UnifiedGraph:
        lateral_rels = {
            RelationshipType.SHARES_SERVER,
            RelationshipType.SHARES_CRED,
            RelationshipType.LATERAL_PATH,
            RelationshipType.USES,
            RelationshipType.EXPOSES_CRED,
            RelationshipType.PROVIDES_TOOL,
            RelationshipType.REACHES_TOOL,
            RelationshipType.VULNERABLE_TO,
        }
        return self._inherit_completeness(self._subgraph(edge_filter=lambda e: e.relationship in lateral_rels))

    def compliance_view(self, framework: str = "") -> UnifiedGraph:
        def node_filter(n: UnifiedNode) -> bool:
            if not n.compliance_tags:
                return False
            if framework:
                return any(framework.upper() in t.upper() for t in n.compliance_tags)
            return True

        return self._inherit_completeness(self._subgraph(node_filter=node_filter))

    def runtime_view(self) -> UnifiedGraph:
        return self._inherit_completeness(self._subgraph(edge_filter=lambda e: e.relationship in _DYNAMIC_RELS))

    def filtered_view(self, filters: GraphFilterOptions) -> UnifiedGraph:
        """Build a subgraph from user-controlled filter options."""
        entity_set = filters.entity_types if filters.entity_types else None
        rel_set = filters.relationship_types if filters.relationship_types else None
        edge_scoped = bool(rel_set or filters.static_only or filters.dynamic_only)

        def node_filter(n: UnifiedNode) -> bool:
            if entity_set and n.entity_type not in entity_set:
                return False
            if filters.min_severity and SEVERITY_RANK.get(n.severity, 0) < SEVERITY_RANK.get(filters.min_severity, 0):
                return False
            if filters.include_ids and n.id not in filters.include_ids:
                return False
            if filters.exclude_ids and n.id in filters.exclude_ids:
                return False
            return True

        def edge_filter(e: UnifiedEdge) -> bool:
            if rel_set and e.relationship not in rel_set:
                return False
            if filters.static_only and e.relationship in _DYNAMIC_RELS:
                return False
            if filters.dynamic_only and e.relationship not in _DYNAMIC_RELS:
                return False
            return True

        sub = self._subgraph(node_filter=node_filter, edge_filter=edge_filter)
        if not edge_scoped:
            return self._inherit_completeness(sub)

        keep_ids = set(filters.include_ids)
        for edge in sub.edges:
            keep_ids.add(edge.source)
            keep_ids.add(edge.target)

        pruned = UnifiedGraph(
            scan_id=sub.scan_id,
            tenant_id=sub.tenant_id,
            created_at=sub.created_at,
            analysis_status=dict(sub.analysis_status),
        )
        for node_id in keep_ids:
            node = sub.nodes.get(node_id)
            if node:
                pruned.add_node(node)
        for edge in sub.edges:
            if edge.source in pruned.nodes and edge.target in pruned.nodes:
                pruned.add_edge(edge)
        return self._inherit_completeness(pruned)

    def _inherit_completeness(
        self,
        view: "UnifiedGraph",
        *,
        truncated: bool = False,
        reason: str = "",
        node_budget: int | None = None,
        depth_limited: bool = False,
    ) -> "UnifiedGraph":
        """Carry the source's truncation onto a derived view.

        Truncation is a property of the SOURCE snapshot. Filtering cannot make
        it untrue: nodes that were never loaded might have matched the filter,
        and nobody can know whether they did. So the flag and reason propagate
        unchanged, ``returned_nodes`` is recomputed for what this view actually
        holds, and ``total_nodes`` stays the upstream total so ``omitted_nodes``
        keeps meaning "how much of the estate we never saw".

        ``truncated`` lets a derivation that bounded itself — a traversal that
        exhausted its node/edge/time budget — OR its own loss in. The source's
        reason wins when both are truncated: it describes the deeper loss, and
        a caller that widens the traversal budget still would not see the nodes
        the loader never fetched.

        Every derived view goes through here — the typed views as much as
        ``filtered_view`` and ``traverse_subgraph`` — so no projection can
        report completeness its source does not have.
        """
        view.completeness.truncated = self.completeness.truncated or truncated
        view.completeness.depth_limited = self.completeness.depth_limited or depth_limited
        view.completeness.node_budget = self.completeness.node_budget if self.completeness.node_budget is not None else node_budget
        view.completeness.reason = self.completeness.reason or (reason if truncated else "")
        # An untruncated graph built by hand never populates total_nodes; falling
        # back to the source's own size keeps `total` from reading as 0 next to a
        # non-empty `returned`.
        view.completeness.total_nodes = self.completeness.total_nodes or len(self.nodes)
        view.completeness.returned_nodes = len(view.nodes)
        return view

    def _subgraph(
        self,
        node_filter: Any = None,
        edge_filter: Any = None,
    ) -> UnifiedGraph:
        sub = UnifiedGraph(
            scan_id=self.scan_id,
            tenant_id=self.tenant_id,
            created_at=self.created_at,
            analysis_status=dict(self.analysis_status),
        )
        if edge_filter and not node_filter:
            matching_edges = [e for e in self.edges if edge_filter(e)]
            referenced_ids = set()
            for e in matching_edges:
                referenced_ids.add(e.source)
                referenced_ids.add(e.target)
            for nid in referenced_ids:
                node = self.nodes.get(nid)
                if node:
                    sub.add_node(node)
            for e in matching_edges:
                sub.add_edge(e)
        elif node_filter:
            node_ids = set()
            for node in self.nodes.values():
                if node_filter(node):
                    sub.add_node(node)
                    node_ids.add(node.id)
            for edge in self.edges:
                if edge.source in node_ids and edge.target in node_ids:
                    if not edge_filter or edge_filter(edge):
                        sub.add_edge(edge)
        return sub


# ── Dynamic relationship set ─────────────────────────────────────────────

_DYNAMIC_RELS = {
    RelationshipType.INVOKED,
    RelationshipType.ACCESSED,
    RelationshipType.DELEGATED_TO,
    RelationshipType.TRACE_STEP,
    RelationshipType.RECORDED_ACTIVITY,
}
