"""Write-time relationship contract for the unified graph.

Every edge must connect an entity pair its :class:`RelationshipSpec` allows and
carry the evidence keys the spec requires. ``AGENT_BOM_GRAPH_CONTRACT`` picks
what happens on a violation:

* ``warn`` (default): keep the edge, log once per (relationship, source kind,
  target kind) and count it in ``analysis_status["relationship_contract"]``.
* ``enforce``: drop an edge whose entity pair is not allowed, log and count it.
* ``strict``: raise :class:`RelationshipContractError` (the test-suite mode).

The pair check runs in ``add_edge`` when both endpoints already exist;
:func:`audit_graph_contract` re-checks the finished graph, including dangling
endpoints and evidence, and records the counts.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from agent_bom.core.settings import env_enum
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import evidence_problems, merge_edge_provenance, normalize_edge_evidence
from agent_bom.graph.relationship_specs import RELATIONSHIP_SPECS, relationship_spec
from agent_bom.graph.types import EntityType

_logger = logging.getLogger(__name__)

CONTRACT_ENV = "AGENT_BOM_GRAPH_CONTRACT"
CONTRACT_MODES = ("warn", "enforce", "strict")
ANALYSIS_KEY = "relationship_contract"
__all__ = ["admit_edge", "audit_graph_contract", "contract_mode", "merge_edge_provenance", "validate_edge"]
_warned: set[tuple[str, str, str, str]] = set()


class RelationshipContractError(ValueError):
    """An edge violates the relationship contract under ``strict`` mode."""


def contract_mode() -> str:
    return env_enum(CONTRACT_ENV, "warn", CONTRACT_MODES)


def _value(kind: Any) -> str:
    return kind.value if hasattr(kind, "value") else str(kind)


def validate_edge(edge: UnifiedEdge, src_type: EntityType | None, tgt_type: EntityType | None) -> list[str]:
    """Return contract problems for ``edge`` given its endpoint entity types."""
    spec = RELATIONSHIP_SPECS.get(edge.relationship) or relationship_spec(edge.relationship)
    if spec is None:
        return ["unregistered_relationship"]
    problems: list[str] = []
    if src_type is None or tgt_type is None:
        problems.append("dangling_endpoint")
    elif not spec.allows(src_type, tgt_type):
        problems.append("pair_not_allowed")
    problems.extend(evidence_problems(edge.evidence, spec.required_evidence))
    return problems


def _report(edge: UnifiedEdge, src: Any, tgt: Any, problem: str, mode: str) -> None:
    key = (_value(edge.relationship), _value(src), _value(tgt), problem)
    if mode == "strict":
        raise RelationshipContractError(
            f"graph relationship contract: {problem} for {key[0]} {key[1]} -> {key[2]} ({edge.source} -> {edge.target})"
        )
    if key not in _warned:
        _warned.add(key)
        _logger.warning("graph relationship contract: %s for %s %s -> %s", problem, key[0], key[1], key[2])


def admit_edge(nodes: Any, edge: UnifiedEdge) -> bool:
    """Normalize evidence and check the entity pair of a new in-memory edge.

    Returns ``False`` only when ``enforce`` mode rejects the edge. Edges whose
    endpoints are not in the graph yet are left to :func:`audit_graph_contract`.
    """
    normalize_edge_evidence(edge.evidence, edge.provenance)
    src = nodes.get(edge.source)
    tgt = nodes.get(edge.target)
    if src is None or tgt is None:
        return True
    spec = RELATIONSHIP_SPECS.get(edge.relationship)  # type: ignore[call-overload]
    if spec is not None and spec.allows(src.entity_type, tgt.entity_type):
        return True
    mode = contract_mode()
    _report(edge, src.entity_type, tgt.entity_type, "pair_not_allowed" if spec else "unregistered_relationship", mode)
    return mode != "enforce"


def audit_graph_contract(graph: Any, *, record: bool = True) -> dict[str, Any]:
    """Check every edge of a finished graph and record the counts.

    Returns ``{"edges_checked": n, "violations": {problem: count},
    "pairs": {"rel src->tgt": count}}``. Under ``strict`` mode any violation
    raises after the counts are recorded.
    """
    problems: Counter[str] = Counter()
    pairs: Counter[str] = Counter()
    checked = 0
    nodes = graph.nodes
    for edge in graph.edges:
        checked += 1
        src = nodes.get(edge.source)
        tgt = nodes.get(edge.target)
        found = validate_edge(edge, src.entity_type if src else None, tgt.entity_type if tgt else None)
        for problem in found:
            problems[problem] += 1
            src_kind = _value(src.entity_type) if src else "<missing>"
            tgt_kind = _value(tgt.entity_type) if tgt else "<missing>"
            pairs[f"{problem}: {_value(edge.relationship)} {src_kind}->{tgt_kind}"] += 1
    summary = {"edges_checked": checked, "violations": dict(problems), "pairs": dict(pairs)}
    if record:
        graph.analysis_status[ANALYSIS_KEY] = GraphAnalysisStatus(
            status=GraphAnalysisState.LIMITED if problems else GraphAnalysisState.COMPLETE,
            reason_codes=tuple(sorted(problems)),
            observed={"edges_checked": checked, **problems},
        )
    if problems:
        mode = contract_mode()
        if mode == "strict":
            raise RelationshipContractError(f"graph relationship contract violations: {dict(sorted(pairs.items()))}")
        for label in sorted(pairs):
            key = ("audit", label, "", "")
            if key not in _warned:
                _warned.add(key)
                _logger.warning("graph relationship contract: %s (%d edges)", label, pairs[label])
    return summary
