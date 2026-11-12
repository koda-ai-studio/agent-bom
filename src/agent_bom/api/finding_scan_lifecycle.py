"""Open/resolved lifecycle of scan-spine findings, stamped on the rows a read serves.

State comes from the job store's durable table, written in the same transaction
as each scan, or from folding retained scans on a store with no such table. See
``docs/FINDING_LIFECYCLE.md``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any

from agent_bom.api.finding_job_metadata import _normalized_evidence_timestamp
from agent_bom.api.finding_lifecycle import lifecycle_fields
from agent_bom.api.finding_lifecycle_fold import FindingState
from agent_bom.api.finding_row_shapes import _package_identity
from agent_bom.evidence.finding_observation import FindingObservationStatus, ReconfirmationReason
from agent_bom.evidence.finding_project import REPORT_ID_FIELD

# A finding in one scope has one state; a finding reported by several sources has one per source.
_Occurrence = tuple[str, str]


def _stamp(row: dict[str, Any], state: FindingState, peers: Sequence[FindingState]) -> dict[str, Any]:
    first_seen = min(peer.first_seen for peer in peers)
    stamped = {**row, "first_seen": first_seen, "last_seen": state.last_seen, "scan_count": sum(peer.scan_count for peer in peers)}
    stamped.update(
        lifecycle_fields(
            state.status,
            first_seen=first_seen,
            resolved_at=state.resolved_at,
            reopened_at=state.reopened_at,
            resolution_reason=state.resolution_reason,
        )
    )
    stamped["resolved_by_scan_id"] = state.resolved_job_id if state.status == "resolved" else None
    return stamped


def _unconfirmed(row: dict[str, Any], state: FindingState) -> dict[str, Any]:
    row["observation_status"] = FindingObservationStatus.UNRECONFIRMED.value
    row["reconfirmation"] = {
        "scan_id": state.unconfirmed_job_id,
        "attempted_at": state.unconfirmed_at,
        "reason_codes": [ReconfirmationReason.ADVISORY_DATA_DEGRADED.value],
    }
    return row


def _row_occurrence(row: dict[str, Any]) -> _Occurrence | None:
    identity = row.get("canonical_id")
    if not isinstance(identity, str) or not identity.strip():
        return None
    asset = row.get("asset")
    environment = row.get("environment") or (asset.get("environment") if isinstance(asset, dict) else None) or ""
    return identity, str(environment)


def _preferred(states: Sequence[FindingState]) -> FindingState:
    """The newest open state, or the latest resolution when every source says it is gone."""
    live = [state for state in states if state.live]
    if live:
        return max(live, key=lambda state: state.last_seen)
    return max(states, key=lambda state: str(state.resolved_at))


def _with_package_identity(row: dict[str, Any]) -> None:
    """A stored stream row keeps its package under ``evidence``; serve it where live rows carry it.

    Only rows that name a package are filled, so a finding on a cloud resource or
    a file never gains its asset's name as a package.
    """
    evidence = row.get("evidence")
    named = isinstance(evidence, dict) and evidence.get("package_name")
    purl = str(row.get("purl") or row.get("package_purl") or "")
    if not (named or row.get("package") or row.get("package_name") or purl.startswith("pkg:")):
        return
    name, version, ecosystem = _package_identity(row)
    if name and not row.get("package"):
        row["package"] = f"{name}@{version}" if version else name
    if version and not row.get("package_version"):
        row["package_version"] = version
    if ecosystem and not row.get("ecosystem"):
        row["ecosystem"] = ecosystem


def _restored_row(state: FindingState, peers: Sequence[FindingState]) -> dict[str, Any]:
    """A row no retained scan serves, rebuilt from durable history with the identity a live row has."""
    source = state.payload or state.new_row or {}
    row = {**source, "canonical_id": state.canonical_id}
    row.setdefault("id", state.canonical_id)
    _with_package_identity(row)
    # The latest scan that reported it; ``scan_id`` filters accept a job id.
    row["scan_id"] = row.get("scan_id") or state.last_job_id or None
    if state.report_canonical_id:
        row[REPORT_ID_FIELD] = state.report_canonical_id
    stamped = _stamp(row, state, peers)
    return _unconfirmed(stamped, state) if state.live and state.unconfirmed_job_id else stamped


def apply_scan_lifecycle(
    rows: list[dict[str, Any]],
    states: Iterable[FindingState],
    *,
    since: str | None,
    live_since: str | None,
    load_payloads: Callable[[list[FindingState]], None],
    finish_rows: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Stamp current rows and append what durable history holds beyond the snapshot.

    Findings a scan disproved come back as ``resolved``, inside ``since``. Open
    findings whose latest scan no longer reports them (the asset stopped being
    scanned, or a scan could not speak for them) stay listed; only an explicit
    window, ``live_since``, narrows those.
    """
    by_occurrence: dict[_Occurrence, list[FindingState]] = {}
    for state in states:
        by_occurrence.setdefault((state.canonical_id, state.environment), []).append(state)
    stamped: list[dict[str, Any]] = []
    served: set[_Occurrence] = set()
    for row in rows:
        key = _row_occurrence(row)
        candidates = by_occurrence.get(key, []) if key is not None else []
        if key is not None:
            served.add(key)
        stamped.append(_stamp(row, _preferred(candidates), candidates) if candidates else {**row, "status": row.get("status") or "open"})
    cutoff = _normalized_evidence_timestamp(since) if since else ""
    live_cutoff = _normalized_evidence_timestamp(live_since) if live_since else ""
    pending: list[tuple[FindingState, list[FindingState]]] = []
    for key, candidates in by_occurrence.items():
        if key in served:
            continue
        state = _preferred(candidates)
        if state.live:
            if state.last_seen >= live_cutoff:
                pending.append((state, candidates))
        elif str(state.resolved_at) >= cutoff:
            pending.append((state, candidates))
    load_payloads([state for state, _ in pending if state.payload is None and state.new_row is None])
    return [*stamped, *finish_rows([_restored_row(state, peers) for state, peers in pending])]


__all__ = ["apply_scan_lifecycle"]
