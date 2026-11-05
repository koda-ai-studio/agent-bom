"""Open/resolved lifecycle of scan-spine findings, derived from retained scans.

Each target scope's scans replay in evidence-time order, so state is a pure
function of the evidence: late arrivals, replays and extra workers cannot move
it. A finding opens when a scan reports it, resolves only when a later complete
scan of the same scope proves it absent, and reopens if it returns. Retention
bounds the replay; see ``docs/FINDING_LIFECYCLE.md``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from agent_bom.api.finding_job_metadata import (
    _normalized_evidence_timestamp,
    _retained_finding_key,
    _ScanJobLike,
    advisory_data_degraded,
    job_has_authoritative_scan_evidence,
    scan_collection_incomplete_reasons,
    scan_evidence_authority_key,
    scan_scope_key,
)
from agent_bom.api.finding_lifecycle import lifecycle_fields
from agent_bom.api.finding_row_shapes import _package_identity
from agent_bom.api.models import JobStatus
from agent_bom.evidence.finding_observation import FindingObservationStatus, ReconfirmationReason

_UNSCOPED_PUSH = "push-unscoped:"
RowsForJob = Callable[[Any], list[dict[str, Any]]]
# Occurrence within a tenant: canonical id + environment, one track per scan scope.
_Occurrence = tuple[str, str, str]


@dataclass(slots=True)
class _Track:
    """One occurrence's state within one target scope."""

    first_seen: str
    last_seen: str
    job: Any
    row: dict[str, Any]
    scope: str
    live: bool = True
    resolved_at: str | None = None
    reopened_at: str | None = None
    scan_count: int = 1
    # The advisory-degraded attempt that could not confirm a still-present package.
    unconfirmed_by: Any = None


def _occurrence(job: _ScanJobLike, row: dict[str, Any], scope: str) -> _Occurrence | None:
    key = _retained_finding_key(job, row, scope=scope)
    return None if key is None else (key[0], key[2], key[3])


def _inventory_packages(result: dict[str, Any]) -> set[tuple[str, str]]:
    """Every ``(name, version)`` the scan inventoried, top level and per MCP server."""
    groups: list[Any] = [result.get("packages")]
    for agent in result.get("agents") or []:
        if isinstance(agent, dict):
            groups.extend(server.get("packages") for server in agent.get("mcp_servers") or [] if isinstance(server, dict))
    found: set[tuple[str, str]] = set()
    for group in groups:
        for package in group if isinstance(group, list) else []:
            if isinstance(package, dict) and package.get("name"):
                found.add((str(package["name"]).strip().lower(), str(package.get("version") or "").strip()))
    return found


def _absence_proves_fix(job: _ScanJobLike, row: dict[str, Any], *, degraded: bool) -> bool:
    """Without advisory data, absence proves a fix only when the package itself is gone."""
    if not degraded:
        return True
    name, version, _ = _package_identity(row)
    if not name:
        return True
    inventory = _inventory_packages(job.result or {})
    return bool(inventory) and (name.lower(), version) not in inventory


def _observed_rows(job: Any, iter_findings: RowsForJob) -> list[dict[str, Any]]:
    """The unified stream carries canonical identity; only legacy reports need the full projection."""
    stream = job.result.get("findings")
    rows = [row for row in stream if isinstance(row, dict)] if isinstance(stream, list) else []
    return rows or iter_findings(job)


def _replay_scope(scope: str, jobs: list[Any], iter_findings: RowsForJob) -> dict[_Occurrence, _Track]:
    tracks: dict[_Occurrence, _Track] = {}
    for job in sorted(jobs, key=scan_evidence_authority_key):
        at = scan_evidence_authority_key(job)[0]
        observed: dict[_Occurrence, dict[str, Any]] = {}
        for row in _observed_rows(job, iter_findings):
            key = _occurrence(job, row, scope)
            if key is not None:
                observed.setdefault(key, row)
        for key, row in observed.items():
            track = tracks.get(key)
            if track is None:
                tracks[key] = _Track(first_seen=at, last_seen=at, job=job, row=row, scope=scope)
                continue
            if not track.live:
                track.live, track.reopened_at = True, at
            track.last_seen, track.job, track.row, track.unconfirmed_by = at, job, row, None
            track.scan_count += 1
        if scan_collection_incomplete_reasons(job):
            continue
        degraded = advisory_data_degraded(job)
        for key, track in tracks.items():
            if not track.live or key in observed:
                continue
            if _absence_proves_fix(job, track.row, degraded=degraded):
                track.live, track.resolved_at, track.unconfirmed_by = False, at, None
            else:
                track.unconfirmed_by = job
    return tracks


def scan_lifecycle_tracks(jobs: Iterable[_ScanJobLike], iter_findings: RowsForJob) -> dict[_Occurrence, list[_Track]]:
    """Replay every executed leaf scan per scope; an occurrence keeps one track per scope."""
    by_scope: dict[str, list[_ScanJobLike]] = {}
    for job in jobs:
        if (
            job.status == JobStatus.DONE
            and isinstance(job.result, dict)
            and not job.child_job_ids
            and job_has_authoritative_scan_evidence(job)
        ):
            by_scope.setdefault(scan_scope_key(job), []).append(job)
    tracks: dict[_Occurrence, list[_Track]] = {}
    for scope, scoped in by_scope.items():
        for key, track in _replay_scope(scope, scoped, iter_findings).items():
            tracks.setdefault(key, []).append(track)
    return tracks


def _stamp(row: dict[str, Any], track: _Track) -> dict[str, Any]:
    status = "resolved" if not track.live else "reopened" if track.reopened_at else "open"
    # A producer's earlier first_seen is kept: its memory may predate retained scans.
    supplied = _normalized_evidence_timestamp(row.get("first_seen"))
    first_seen = min(supplied, track.first_seen) if supplied else track.first_seen
    stamped = {**row, "first_seen": first_seen, "last_seen": track.last_seen, "scan_count": track.scan_count}
    stamped.update(lifecycle_fields(status, first_seen=first_seen, resolved_at=track.resolved_at, reopened_at=track.reopened_at))
    return stamped


def _unscoped_first_seen(track: _Track, candidates: list[_Track]) -> _Track:
    """Pushes without a target identity are independent evidence of one occurrence, so their dates join."""
    if not track.scope.startswith(_UNSCOPED_PUSH):
        return track
    peers = [item for item in candidates if item.scope.startswith(_UNSCOPED_PUSH)]
    return replace(track, first_seen=min(item.first_seen for item in peers), scan_count=sum(item.scan_count for item in peers))


def _unconfirmed(row: dict[str, Any], attempt: _ScanJobLike) -> dict[str, Any]:
    row["observation_status"] = FindingObservationStatus.UNRECONFIRMED.value
    row["reconfirmation"] = {
        "scan_id": attempt.job_id,
        "attempted_at": scan_evidence_authority_key(attempt)[0] or None,
        "reason_codes": [ReconfirmationReason.ADVISORY_DATA_DEGRADED.value],
    }
    return row


def _row_occurrence(row: dict[str, Any], tenant_id: str) -> _Occurrence | None:
    identity = row.get("canonical_id")
    if not isinstance(identity, str) or not identity.strip():
        return None
    asset = row.get("asset")
    environment = row.get("environment") or (asset.get("environment") if isinstance(asset, dict) else None) or ""
    return tenant_id, identity, str(environment)


def _restored_rows(
    pending: list[tuple[_Occurrence, _Track, Any]],
    jobs: Sequence[_ScanJobLike],
    iter_findings: RowsForJob,
    retained_history: Callable[..., dict[Any, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Enriched rows from each track's last scan, keeping manual SLA assignments."""
    from agent_bom.graph.sla import merge_finding_sla

    wanted = {(key[0], track.scope, key[1], key[2]) for key, track, _ in pending}
    history = retained_history(list(jobs), wanted, require_authoritative_evidence=False) if wanted else {}
    restored: list[dict[str, Any]] = []
    for key, track, attempt in pending:
        source = next((row for row in iter_findings(track.job) if _occurrence(track.job, row, track.scope) == key), track.row)
        row = _stamp(source, track)
        previous = history.get((key[0], track.scope, key[1], key[2]))
        if previous:
            first_seen = str(row["first_seen"])
            row = {**merge_finding_sla(row, previous, first_seen=first_seen), "first_seen": first_seen}
        restored.append(_unconfirmed(row, attempt) if attempt is not None else row)
    return restored


def apply_scan_lifecycle(
    rows: list[dict[str, Any]],
    jobs: Sequence[_ScanJobLike],
    *,
    since: str | None,
    iter_findings: RowsForJob,
    in_window: Callable[[Any, str | None], bool],
    retained_history: Callable[..., dict[Any, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Stamp current rows and append what the replay retains beyond the snapshot.

    Occurrences a complete scan disproved come back as ``resolved``; one whose
    package is present but whose scan lacked advisory data stays open as
    unreconfirmed. The window applies to the resolution or last observation.
    """
    tenant_id = str(getattr(jobs[0], "tenant_id", "default")) if jobs else "default"
    tracks = scan_lifecycle_tracks(jobs, iter_findings)
    stamped: list[dict[str, Any]] = []
    served: set[_Occurrence] = set()
    for row in rows:
        key = _row_occurrence(row, tenant_id)
        candidates = tracks.get(key, []) if key is not None else []
        live = [track for track in candidates if track.live]
        if key is not None:
            served.add(key)
        # The selected row is the newest scan's, so its dates are the newest live track's.
        if live:
            stamped.append(_stamp(row, _unscoped_first_seen(max(live, key=lambda track: track.last_seen), candidates)))
        else:
            stamped.append({**row, "status": row.get("status") or "open"})
    cutoff = _normalized_evidence_timestamp(since) if since else ""
    pending: list[tuple[_Occurrence, _Track, Any]] = []
    for key, candidates in tracks.items():
        if key in served:
            continue
        live = [track for track in candidates if track.live and track.unconfirmed_by is not None and in_window(track.job, since)]
        if live:
            track = max(live, key=lambda item: item.last_seen)
            pending.append((key, track, track.unconfirmed_by))
        elif not any(track.live for track in candidates):
            track = max(candidates, key=lambda item: str(item.resolved_at))
            if not cutoff or str(track.resolved_at) >= cutoff:
                pending.append((key, track, None))
    return [*stamped, *_restored_rows(pending, jobs, iter_findings, retained_history)]


__all__ = ["apply_scan_lifecycle", "scan_lifecycle_tracks"]
