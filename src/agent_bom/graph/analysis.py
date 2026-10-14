"""Typed execution status for snapshot-wide graph analyses."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable, Mapping

if TYPE_CHECKING:
    from agent_bom.evidence.semantics import CompletenessEntry


class GraphAnalysisState(str, Enum):
    COMPLETE = "complete"
    LIMITED = "limited"
    SKIPPED = "skipped"
    FAILED = "failed"
    NOT_RECORDED = "not_recorded"


@dataclass(frozen=True, slots=True)
class GraphAnalysisStatus:
    """Secret-safe, serializable status for one graph analyzer."""

    status: GraphAnalysisState
    reason_codes: tuple[str, ...] = ()
    limits: Mapping[str, int] = field(default_factory=dict)
    observed: Mapping[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "limits": {str(key): int(value) for key, value in self.limits.items()},
            "observed": {str(key): int(value) for key, value in self.observed.items()},
        }

    def to_completeness_entry(self, *, component: str) -> CompletenessEntry:
        """Project this analyzer status without changing snapshot serialization."""

        from agent_bom.evidence.semantics import CompletenessEntry, EvidenceStage, EvidenceStatus

        status_map = {
            GraphAnalysisState.COMPLETE: EvidenceStatus.COMPLETE,
            GraphAnalysisState.LIMITED: EvidenceStatus.PARTIAL,
            GraphAnalysisState.SKIPPED: EvidenceStatus.UNAVAILABLE,
            GraphAnalysisState.FAILED: EvidenceStatus.FAILED,
            GraphAnalysisState.NOT_RECORDED: EvidenceStatus.UNAVAILABLE,
        }
        reasons = self.reason_codes
        if not reasons and self.status is not GraphAnalysisState.COMPLETE:
            reasons = (self.status.value,)
        return CompletenessEntry(
            stage=EvidenceStage.ANALYSIS,
            component=component,
            status=status_map[self.status],
            returned_count=max(self.observed.values(), default=None),
            reason_codes=reasons,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GraphAnalysisStatus:
        try:
            state = GraphAnalysisState(str(data.get("status", "not_recorded")))
        except ValueError:
            state = GraphAnalysisState.NOT_RECORDED
        return cls(
            status=state,
            reason_codes=tuple(str(code) for code in data.get("reason_codes", ()) if isinstance(code, str) and code),
            limits=_integer_mapping(data.get("limits")),
            observed=_integer_mapping(data.get("observed")),
        )


def _integer_mapping(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, int] = {}
    for key, candidate in value.items():
        if isinstance(candidate, bool):
            continue
        try:
            result[str(key)] = int(candidate)
        except (TypeError, ValueError):
            continue
    return result


def analysis_status_map_to_dict(statuses: Mapping[str, GraphAnalysisStatus]) -> dict[str, dict[str, Any]]:
    return {str(name): status.to_dict() for name, status in sorted(statuses.items())}


def analysis_status_map_from_dict(value: Any) -> dict[str, GraphAnalysisStatus]:
    if not isinstance(value, Mapping):
        value = {}
    statuses = {str(name): GraphAnalysisStatus.from_dict(payload) for name, payload in value.items() if isinstance(payload, Mapping)}
    if "attack_path_fusion" not in statuses:
        statuses["attack_path_fusion"] = not_recorded_analysis_status()
    return statuses


def not_recorded_analysis_status() -> GraphAnalysisStatus:
    return GraphAnalysisStatus(
        status=GraphAnalysisState.NOT_RECORDED,
        reason_codes=("legacy_snapshot",),
    )


# Higher is less trustworthy: a merged view is only as complete as its worst source.
_SEVERITY = {
    GraphAnalysisState.COMPLETE: 0,
    GraphAnalysisState.LIMITED: 1,
    GraphAnalysisState.NOT_RECORDED: 2,
    GraphAnalysisState.SKIPPED: 3,
    GraphAnalysisState.FAILED: 4,
}


def merge_analysis_statuses(sources: Iterable[Mapping[str, GraphAnalysisStatus]]) -> dict[str, GraphAnalysisStatus]:
    """Combine per-source analyzer statuses for a view assembled from several snapshots.

    The worst state wins, reason codes are unioned so no source's bound is
    hidden, configured limits keep their largest value and observed counts add.
    """
    grouped: dict[str, list[GraphAnalysisStatus]] = {}
    for source in sources:
        for name, entry in source.items():
            grouped.setdefault(str(name), []).append(entry)
    merged: dict[str, GraphAnalysisStatus] = {}
    for name, statuses in sorted(grouped.items()):
        if len(statuses) == 1:
            merged[name] = statuses[0]
            continue
        limits: dict[str, int] = {}
        observed: dict[str, int] = {}
        for status in statuses:
            for key, value in status.limits.items():
                limits[key] = max(limits.get(key, value), value)
            for key, value in status.observed.items():
                observed[key] = observed.get(key, 0) + value
        merged[name] = GraphAnalysisStatus(
            status=max((status.status for status in statuses), key=_SEVERITY.__getitem__),
            reason_codes=tuple(sorted({code for status in statuses for code in status.reason_codes})),
            limits=limits,
            observed=observed,
        )
    return merged
