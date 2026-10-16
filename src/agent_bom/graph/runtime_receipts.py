"""Keep runtime observations separate when a canonical edge has several sources."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Protocol

from agent_bom.graph.types import RelationshipType


class RuntimeEdge(Protocol):
    @property
    def relationship(self) -> RelationshipType | str: ...

    @property
    def evidence(self) -> dict[str, Any]: ...

    @property
    def provenance(self) -> dict[str, Any]: ...


MAX_RUNTIME_RECEIPTS = 16
_FIELDS = (
    "source",
    "tier",
    "event_id",
    "trace_id",
    "sample_trace_ids",
    "observed_at",
    "timestamp",
    "blocked",
    "decision",
    "runtime_observed_state",
    "runtime_observed",
    "observation_count",
    "failure_count",
    "count",
    "error_count",
)
_SIGNALS = (
    "event_id",
    "trace_id",
    "sample_trace_ids",
    "blocked",
    "runtime_observed_state",
    "runtime_observed",
    "failure_count",
    "error_count",
)


def runtime_records(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Return source records, never mix an event from one with another trace."""
    rows = evidence.get("runtime_receipts")
    if "runtime_receipts" in evidence:
        return [row for row in rows[:MAX_RUNTIME_RECEIPTS] if isinstance(row, dict)] if isinstance(rows, list) else []
    if evidence.get("tier") == "runtime_observed" or any(key in evidence for key in _SIGNALS):
        return [{key: deepcopy(evidence[key]) for key in _FIELDS if key in evidence}]
    return []


def runtime_receipts_limited(evidence: dict[str, Any]) -> bool:
    """Missing or bounded source records cannot establish a complete hop."""
    if evidence.get("runtime_receipts_truncated") is True:
        return True
    if "runtime_receipts" not in evidence:
        return False
    rows = evidence["runtime_receipts"]
    return (
        not isinstance(rows, list)
        or not rows
        or len(rows) > MAX_RUNTIME_RECEIPTS
        or any(not isinstance(row, dict) or not any(key in row for key in _SIGNALS) for row in rows)
    )


def merge_runtime_receipts(stored: dict[str, Any], incoming: dict[str, Any]) -> bool:
    """Bounded union of whole observations; compatibility scalars are not proof."""
    records = {}
    for evidence in (stored, incoming):
        for row in runtime_records(evidence):
            receipt = {key: deepcopy(row[key]) for key in _FIELDS if key in row}
            records[json.dumps(receipt, sort_keys=True, default=str)] = receipt
    limited = any(runtime_receipts_limited(evidence) for evidence in (stored, incoming)) or len(records) > MAX_RUNTIME_RECEIPTS
    if not records and not limited:
        return False
    rows = [records[key] for key in sorted(records)[:MAX_RUNTIME_RECEIPTS]]
    changed = stored.get("runtime_receipts") != rows or (limited and stored.get("runtime_receipts_truncated") is not True)
    stored["runtime_receipts"] = rows
    if limited:
        stored["runtime_receipts_truncated"] = True
    return changed


_RUNTIME_RELATIONSHIPS = frozenset(
    {
        RelationshipType.INVOKED.value,
        RelationshipType.ACCESSED.value,
    }
)


def runtime_state(edge: RuntimeEdge) -> str:
    # A denial is an observed attempt, never evidence of a completed action.
    # Negative facts win even if another source supplied an "observed" label.
    if (
        edge.evidence.get("blocked") is True
        or edge.evidence.get("decision") in ("blocked", "denied", "explicit_deny", "implicit_deny")
        or edge.evidence.get("runtime_observed_state") == "blocked"
        or edge.provenance.get("runtime_observed_state") == "blocked"
    ):
        return "blocked"
    if any(
        record.get("blocked") is True
        or record.get("decision") in ("blocked", "denied", "explicit_deny", "implicit_deny")
        or record.get("runtime_observed_state") == "blocked"
        for record in runtime_records(edge.evidence)
    ):
        return "blocked"
    explicit = edge.evidence.get("runtime_observed_state") or edge.provenance.get("runtime_observed_state")
    if explicit in ("observed", "blocked", "not_observed"):
        return str(explicit)
    if getattr(edge.relationship, "value", edge.relationship) in _RUNTIME_RELATIONSHIPS or edge.evidence.get("runtime_observed"):
        return "observed"
    return "not_observed"


def runtime_outcome(edge: RuntimeEdge) -> str:
    """Retain failed aggregate attempts without inferring downstream success."""
    if runtime_state(edge) == "blocked":
        return "blocked"
    for record in runtime_records(edge.evidence):
        observed = record.get("observation_count", record.get("count"))
        failed = record.get("failure_count", record.get("error_count"))
        if type(observed) is int and type(failed) is int and observed > 0 and failed == observed:
            return "failed"
    # A permitted invocation or an event without an error is not an outcome
    # receipt. Mixed aggregates also cannot identify which action succeeded.
    return "unknown"
