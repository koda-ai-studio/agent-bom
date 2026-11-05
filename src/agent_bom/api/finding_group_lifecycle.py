"""An issue's lifecycle, folded from its occurrences: open until every one is resolved."""

from __future__ import annotations

from typing import Any

from agent_bom.api.finding_job_metadata import _normalized_evidence_timestamp
from agent_bom.api.finding_lifecycle import lifecycle_fields

GROUP_LIFECYCLE_KEYS = (
    "status",
    "first_seen",
    "last_seen",
    "resolved_at",
    "last_resolved_at",
    "reopened_at",
    "status_updated_at",
    "open_occurrence_count",
    "resolved_occurrence_count",
)


def new_group_lifecycle() -> dict[str, Any]:
    return {"open": 0, "resolved": 0, "reopened": 0, "first_seen": "", "last_seen": "", "resolved_at": "", "reopened_at": ""}


def _pick(current: str, candidate: Any, *, latest: bool) -> str:
    """Keep the earliest or latest instant, compared in UTC; the original spelling is kept."""
    value = str(candidate or "")
    key = _normalized_evidence_timestamp(value)
    if not key:
        return current
    if not current:
        return value
    held = _normalized_evidence_timestamp(current)
    return value if (key > held if latest else key < held) else current


def record_group_occurrence(state: dict[str, Any], row: dict[str, Any]) -> None:
    status = str(row.get("status") or "open")
    if status == "resolved":
        state["resolved"] += 1
    else:
        state["open"] += 1
        state["reopened"] += int(status == "reopened")
    state["first_seen"] = _pick(state["first_seen"], row.get("first_seen"), latest=False)
    state["last_seen"] = _pick(state["last_seen"], row.get("last_seen"), latest=True)
    state["resolved_at"] = _pick(state["resolved_at"], row.get("resolved_at") or row.get("last_resolved_at"), latest=True)
    state["reopened_at"] = _pick(state["reopened_at"], row.get("reopened_at"), latest=True)


def group_lifecycle_fields(state: dict[str, Any]) -> dict[str, Any]:
    status = "resolved" if not state["open"] else "reopened" if state["reopened"] else "open"
    fields = lifecycle_fields(
        status,
        first_seen=state["first_seen"],
        resolved_at=state["resolved_at"] or None,
        reopened_at=state["reopened_at"] or None,
    )
    return {
        **fields,
        "first_seen": state["first_seen"] or None,
        "last_seen": state["last_seen"] or None,
        "open_occurrence_count": state["open"],
        "resolved_occurrence_count": state["resolved"],
    }
