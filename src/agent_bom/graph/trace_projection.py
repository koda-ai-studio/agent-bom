"""Aggregate normalized trace events into runtime-observed graph edges.

Spans bind to inventory only through exact identifiers: a node id or canonical
id the source reported, or a credential slot id composed from a bound server and
an exact credential name. A name that merely equals an inventory label is a
candidate: it is counted, never drawn as an edge, and never feeds path analysis.
Edges aggregate per (source node, relationship, target node) inside a fixed
window, so identical input always yields identical edges.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.runtime.normalized_trace import NormalizedTraceEvent
from agent_bom.security import sanitize_sensitive_payload, sanitize_text

TRACE_SOURCE = "runtime-trace"
STATUS_KEY = "runtime_trace_projection"
MAX_EVENTS = 20_000
SAMPLE_TRACE_IDS = 5
_MAX_PARENT_HOPS = 32

E = EntityType
R = RelationshipType
_REL_BY_TARGET: dict[EntityType, RelationshipType] = {
    E.TOOL: R.INVOKED,
    E.SERVER: R.CALLED,
    E.CREDENTIAL: R.USED_CREDENTIAL,
    E.CREDENTIAL_REF: R.USED_CREDENTIAL,
    E.CLOUD_RESOURCE: R.ACCESSED,
    E.DATA_STORE: R.ACCESSED,
    E.DATASET: R.ACCESSED,
    E.RESOURCE: R.ACCESSED,
}
_NAMED_KINDS = {"agent": E.AGENT, "tool": E.TOOL, "mcp": E.SERVER}


@dataclass
class _Aggregate:
    count: int = 0
    errors: int = 0
    first_seen: str = ""
    last_seen: str = ""
    sources: set[str] = field(default_factory=set)
    trace_ids: set[str] = field(default_factory=set)
    signals: set[str] = field(default_factory=set)

    def add(self, event: NormalizedTraceEvent) -> None:
        moment = event.started_at or ""
        self.count += 1
        self.errors += event.status == "error"
        self.first_seen = min(self.first_seen or moment, moment)
        self.last_seen = max(self.last_seen, moment)
        self.sources.add(event.source)
        self.signals.update(event.signals)
        if event.source_trace_id:
            self.trace_ids.add(event.source_trace_id[:128])


@dataclass(frozen=True)
class ShadowEntity:
    """A runtime-named agent/tool with neither an exact nor a name-candidate inventory match."""

    kind: str
    name: str
    source: str
    count: int
    first_seen: str
    last_seen: str
    agent_node_id: str | None
    sample_trace_ids: tuple[str, ...]


@dataclass
class TraceProjectionResult:
    observed: dict[str, int]
    edges: int = 0
    shadow: list[ShadowEntity] = field(default_factory=list)
    window_start: str = ""
    window_end: str = ""


class _Binder:
    """Exact node and canonical-id lookups against the graph being built."""

    def __init__(self, graph: UnifiedGraph) -> None:
        self.graph = graph
        self._canonical: dict[str, str] | None = None
        self._names: dict[tuple[EntityType, str], list[str]] | None = None

    def node(self, ref: str | None) -> UnifiedNode | None:
        if not ref:
            return None
        if self.graph.has_node(ref):
            return self.graph.get_node(ref)
        if self._canonical is None:
            self._canonical = {
                str(node.attributes["canonical_id"]): node.id
                for kind in (E.AGENT, E.TOOL, E.SERVER, E.CREDENTIAL, E.CLOUD_RESOURCE, E.DATASET, E.DATA_STORE)
                for node in self.graph.iter_nodes_by_type(kind)
                if isinstance(node.attributes.get("canonical_id"), str)
            }
        node_id = self._canonical.get(ref)
        return self.graph.get_node(node_id) if node_id else None

    def name_candidates(self, entity_type: EntityType, name: str) -> list[str]:
        if self._names is None:
            self._names = {}
            for kind in _NAMED_KINDS.values():
                for node in self.graph.iter_nodes_by_type(kind):
                    for label in {node.label, str(node.attributes.get("name") or "")} - {""}:
                        self._names.setdefault((kind, label.lower()), []).append(node.id)
        return sorted(self._names.get((entity_type, name.lower()), []))

    def credential(self, holder: UnifiedNode, server: UnifiedNode | None, name: str) -> UnifiedNode | None:
        servers = [server.id] if server is not None else self._servers_of(holder)
        for server_id in servers:
            node = self.node(f"cred:{server_id}:{name}")
            if node is not None and node.entity_type in (E.CREDENTIAL, E.CREDENTIAL_REF):
                return node
        return None

    def _servers_of(self, holder: UnifiedNode) -> list[str]:
        if holder.entity_type == E.TOOL:
            edges = self.graph.reverse_adjacency.get(holder.id, [])
            return sorted({edge.source for edge in edges if edge.relationship == R.PROVIDES_TOOL})
        edges = self.graph.adjacency.get(holder.id, [])
        return sorted({edge.target for edge in edges if edge.relationship == R.USES})


def _parse_moment(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _admit(
    events: Iterable[Mapping[str, Any]], tenant_id: str, start: datetime, end: datetime, observed: dict[str, int]
) -> list[NormalizedTraceEvent]:
    admitted: list[NormalizedTraceEvent] = []
    for raw in events:
        try:
            event = NormalizedTraceEvent.from_dict(raw)
        except (TypeError, ValueError):
            observed["invalid_events"] += 1
            continue
        if event.tenant_id != tenant_id:
            observed["tenant_rejected"] += 1
            continue
        moment = _parse_moment(event.started_at)
        if moment is None:
            observed["untimed_events"] += 1
        elif not start <= moment <= end:
            observed["out_of_window"] += 1
        else:
            admitted.append(event)
    admitted.sort(key=lambda item: (item.started_at or "", item.source, item.source_trace_id, item.source_span_id), reverse=True)
    observed["truncated_events"] = max(0, len(admitted) - MAX_EVENTS)
    return admitted[:MAX_EVENTS]


class _Projector:
    def __init__(self, graph: UnifiedGraph, events: list[NormalizedTraceEvent], observed: dict[str, int]) -> None:
        self.binder = _Binder(graph)
        self.graph = graph
        self.observed = observed
        self.spans = {(event.source, event.source_trace_id, event.source_span_id): event for event in events}
        self.bound: dict[tuple[str, str, str], UnifiedNode | None] = {}
        self.aggregates: dict[tuple[str, str, str], _Aggregate] = {}
        self.shadow: dict[tuple[str, str, str], tuple[_Aggregate, str | None]] = {}

    def own_node(self, event: NormalizedTraceEvent) -> UnifiedNode | None:
        key = (event.source, event.source_trace_id, event.source_span_id)
        if key not in self.bound:
            self.bound[key] = self.binder.node(event.match_node_id) if event.match_method == "exact" else None
        return self.bound[key]

    def agent_for(self, event: NormalizedTraceEvent) -> UnifiedNode | None:
        agent = self.binder.node(event.agent_ref)
        if agent is not None and agent.entity_type == E.AGENT:
            return agent
        current: NormalizedTraceEvent | None = event
        for _ in range(_MAX_PARENT_HOPS):
            if current is None or not current.parent_span_id:
                return None
            current = self.spans.get((current.source, current.source_trace_id, current.parent_span_id))
            node = self.own_node(current) if current is not None else None
            if node is not None and node.entity_type == E.AGENT:
                return node
        return None

    def link(
        self, source: UnifiedNode | None, relationship: RelationshipType, target: UnifiedNode | None, event: NormalizedTraceEvent
    ) -> None:
        if source is None or target is None or source.id == target.id:
            return
        spec = relationship_spec(relationship)
        if spec is None or not spec.allows(source.entity_type, target.entity_type):
            self.observed["disallowed_pairs"] += 1
            return
        self.aggregates.setdefault((source.id, relationship.value, target.id), _Aggregate()).add(event)

    def project(self, event: NormalizedTraceEvent) -> None:
        own = self.own_node(event)
        if event.match_method == "exact" and own is None:
            self.observed["stale_exact_refs"] += 1
        if own is not None:
            self.observed["exact_bound"] += 1
        else:
            self._classify_unbound(event)
        agent = own if own is not None and own.entity_type == E.AGENT else self.agent_for(event)
        relationship = _REL_BY_TARGET.get(own.entity_type) if own is not None else None
        if relationship is not None:
            self.link(agent, relationship, own, event)
        server = self.binder.node(event.mcp_server_ref)
        server = server if server is not None and server.entity_type == E.SERVER else None
        self.link(agent, R.CALLED, server, event)
        actor = own if own is not None and own.entity_type == E.TOOL else agent
        for ref in event.resource_refs:
            target = self.binder.node(ref)
            if target is not None and _REL_BY_TARGET.get(target.entity_type) == R.ACCESSED:
                self.link(actor, R.ACCESSED, target, event)
        if event.credential_ref and actor is not None:
            credential = self.binder.credential(actor, server, event.credential_ref)
            if credential is None:
                self.observed["unbound_credential_refs"] += 1
            self.link(actor, R.USED_CREDENTIAL, credential, event)

    def _classify_unbound(self, event: NormalizedTraceEvent) -> None:
        name = {"agent": event.agent_name, "tool": event.tool_name, "mcp": event.mcp_server_ref}.get(event.kind)
        entity_type = _NAMED_KINDS.get(event.kind)
        if not name or entity_type is None:
            self.observed["unbound_context_spans"] += 1
            return
        if self.binder.name_candidates(entity_type, name):
            self.observed["name_candidates"] += 1
            return
        self.observed["unmatched_named_spans"] += 1
        if event.kind in ("agent", "tool"):
            agent = self.agent_for(event)
            key = (event.kind, name.lower(), event.source)
            aggregate, _ = self.shadow.setdefault(key, (_Aggregate(), agent.id if agent is not None else None))
            aggregate.add(event)


def _evidence(aggregate: _Aggregate, start: str, end: str) -> dict[str, Any]:
    evidence = edge_evidence(
        TRACE_SOURCE,
        "runtime_observed",
        basis="exact_inventory_id",
        match_method="exact",
        count=aggregate.count,
        error_count=aggregate.errors,
        first_seen=aggregate.first_seen,
        last_seen=aggregate.last_seen,
        observed_at=aggregate.last_seen,
        trace_sources=sorted(aggregate.sources),
        sample_trace_ids=sorted(aggregate.trace_ids)[:SAMPLE_TRACE_IDS],
        signals=sorted(aggregate.signals),
        window_start=start,
        window_end=end,
    )
    sanitized = sanitize_sensitive_payload(evidence)
    return sanitized if isinstance(sanitized, dict) else evidence


def _annotate(graph: UnifiedGraph, node_id: str, relationship: str, aggregate: _Aggregate) -> None:
    node = graph.get_node(node_id)
    if node is None:
        return
    prior = node.attributes.get("runtime_trace_use")
    prior = prior if isinstance(prior, dict) else {}
    node.attributes["runtime_trace_use"] = {
        "count": int(prior.get("count") or 0) + aggregate.count,
        "first_seen": min(str(prior.get("first_seen") or aggregate.first_seen), aggregate.first_seen),
        "last_seen": max(str(prior.get("last_seen") or ""), aggregate.last_seen),
        "relationships": sorted({*prior.get("relationships", []), relationship}),
        "source": TRACE_SOURCE,
    }
    if node.entity_type in (E.CREDENTIAL, E.CREDENTIAL_REF):
        node.attributes["runtime_used"] = True


def project_trace_events(
    graph: UnifiedGraph,
    events: Iterable[Mapping[str, Any]],
    *,
    tenant_id: str,
    window_start: str,
    window_end: str,
) -> TraceProjectionResult:
    """Draw aggregated runtime edges for exactly bound spans and report the rest."""
    observed = dict.fromkeys(
        (
            "events",
            "invalid_events",
            "tenant_rejected",
            "untimed_events",
            "out_of_window",
            "truncated_events",
            "exact_bound",
            "stale_exact_refs",
            "name_candidates",
            "unmatched_named_spans",
            "unbound_context_spans",
            "unbound_credential_refs",
            "disallowed_pairs",
            "edges",
            "shadow_entities",
        ),
        0,
    )
    start, end = _parse_moment(window_start), _parse_moment(window_end)
    if start is None or end is None or start > end or not tenant_id:
        raise ValueError("Trace projection requires a tenant and a valid fixed window")
    admitted = _admit(events, tenant_id, start, end, observed)
    observed["events"] = len(admitted)
    projector = _Projector(graph, admitted, observed)
    for event in admitted:
        projector.project(event)
    for (source_id, relationship, target_id), aggregate in sorted(projector.aggregates.items()):
        graph.add_edge(
            UnifiedEdge(
                source=source_id,
                target=target_id,
                relationship=RelationshipType(relationship),
                evidence=_evidence(aggregate, window_start, window_end),
                provenance={"source": TRACE_SOURCE},
            )
        )
        _annotate(graph, target_id, relationship, aggregate)
    shadow = [
        ShadowEntity(
            kind=kind,
            name=sanitize_text(name, max_len=300),
            source=source,
            count=aggregate.count,
            first_seen=aggregate.first_seen,
            last_seen=aggregate.last_seen,
            agent_node_id=agent_id,
            sample_trace_ids=tuple(sorted(aggregate.trace_ids)[:SAMPLE_TRACE_IDS]),
        )
        for (kind, name, source), (aggregate, agent_id) in sorted(projector.shadow.items())
    ]
    observed["edges"] = len(projector.aggregates)
    observed["shadow_entities"] = len(shadow)
    limited = observed["truncated_events"] > 0
    reasons = tuple(
        code
        for code, count in (("event_cap", observed["truncated_events"]), ("unmatched_named_spans", observed["unmatched_named_spans"]))
        if count
    )
    graph.analysis_status[STATUS_KEY] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if limited else GraphAnalysisState.COMPLETE,
        reason_codes=reasons,
        limits={"max_events": MAX_EVENTS},
        observed=observed,
    )
    return TraceProjectionResult(
        observed=observed, edges=observed["edges"], shadow=shadow, window_start=window_start, window_end=window_end
    )


def project_report_trace_events(graph: UnifiedGraph, payload: object, tenant_id: str) -> TraceProjectionResult | None:
    """Builder entry point: ``payload`` is ``{"events", "window_start", "window_end"}``.

    The control plane loads the events from tenant-scoped trace storage. A build
    without that section is unchanged.
    """
    if not isinstance(payload, Mapping):
        return None
    if payload.get("load_failed"):
        graph.analysis_status[STATUS_KEY] = GraphAnalysisStatus(status=GraphAnalysisState.FAILED, reason_codes=("trace_store_unavailable",))
        return None
    events = payload.get("events")
    try:
        result = project_trace_events(
            graph,
            events if isinstance(events, list) else [],
            tenant_id=tenant_id,
            window_start=str(payload.get("window_start") or ""),
            window_end=str(payload.get("window_end") or ""),
        )
    except ValueError:
        graph.analysis_status[STATUS_KEY] = GraphAnalysisStatus(status=GraphAnalysisState.SKIPPED, reason_codes=("invalid_window",))
        return None
    if payload.get("load_truncated"):
        status = graph.analysis_status[STATUS_KEY]
        reasons = (*status.reason_codes, "load_cap")
        graph.analysis_status[STATUS_KEY] = GraphAnalysisStatus(GraphAnalysisState.LIMITED, reasons, status.limits, status.observed)
    graph.runtime_trace_projection = result
    return result
