"""One finding's lifecycle as state folded from scan evidence, in any arrival order.

Dates merge monotonically: ``first_seen`` is the earliest observation and
``last_seen`` the latest. A finding is resolved when a complete scan newer than
its latest observation proved it absent, at the earliest such scan. Those rules
do not depend on arrival order, so late, replayed and concurrent scans reach the
same state. One detail is bounded rather than exact: a complete scan arriving
after a newer sighting records a reopen dated at that newest sighting, because
the sightings in between are not kept.
"""

from __future__ import annotations

import bisect
import hashlib
import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_bom.api.finding_job_metadata import (
    _normalized_evidence_timestamp,
    _ScanJobLike,
    advisory_data_degraded,
    job_has_authoritative_scan_evidence,
    scan_collection_incomplete_reasons,
    scan_evidence_authority_key,
    scan_scope_key,
)
from agent_bom.api.finding_row_shapes import _package_identity
from agent_bom.api.models import JobStatus
from agent_bom.evidence.asset_coverage import DeletionProof, asset_location, deletion_proof
from agent_bom.evidence.finding_project import REPORT_ID_FIELD, finding_project_key, with_project_identity

REASON_NOT_DETECTED = "no_longer_detected"
REASON_ASSET_DELETED = "asset_deleted"
_UNSCOPED_PUSH = "push-unscoped:"
# These differ on every scan of an unchanged finding, so they must not count as a changed row.
_PER_SCAN_FIELDS = frozenset({"scan_id", "first_seen", "last_seen", "last_observed", "observed_at", "generated_at"})
RowsForJob = Callable[[Any], list[dict[str, Any]]]
StateKey = tuple[str, str]


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, separators=(",", ":"), sort_keys=True, default=str).encode()).hexdigest()


@dataclass(slots=True)
class Observation:
    canonical_id: str
    environment: str
    report_canonical_id: str | None
    row: dict[str, Any]
    row_hash: str
    first_seen: str
    asset_key: str | None
    coverage_key: str | None


@dataclass(slots=True)
class ScanEvidence:
    tenant_id: str
    job_id: str
    scope_hash: str
    at: str
    unscoped: bool
    proves_absence: bool
    degraded: bool
    observed: dict[str, Observation]
    packages: set[tuple[str, str]]
    proof: DeletionProof | None

    @property
    def complete(self) -> bool:
        """Evidence that any finding absent from it, on any asset, is gone."""
        return self.proves_absence and not self.degraded and not self.unscoped


@dataclass(slots=True)
class FindingState:
    scope_hash: str
    finding_key: str
    canonical_id: str
    environment: str
    report_canonical_id: str | None
    first_seen: str
    last_seen: str
    status: str = "open"
    resolved_at: str | None = None
    resolution_reason: str | None = None
    reopened_at: str | None = None
    scan_count: int = 1
    last_job_id: str = ""
    unconfirmed_job_id: str | None = None
    unconfirmed_at: str | None = None
    asset_key: str | None = None
    coverage_key: str | None = None
    payload_hash: str | None = None
    payload: dict[str, Any] | None = None
    new_row: dict[str, Any] | None = field(default=None, repr=False)
    changed: bool = False

    @property
    def live(self) -> bool:
        return self.status != "resolved"

    def resolve(self, at: str, reason: str) -> None:
        self.status, self.resolved_at, self.resolution_reason = "resolved", at, reason
        self.unconfirmed_job_id, self.unconfirmed_at = None, None


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


def _track_scope(job: _ScanJobLike, *, unscoped: bool) -> str:
    """Pushes with no target identity share one track per source, so their rows do not multiply per push."""
    key = scan_scope_key(job)
    return _digest(f"{_UNSCOPED_PUSH}{getattr(job, 'source_id', None) or ''}" if unscoped else key)


def finding_key(canonical_id: str, environment: str) -> str:
    return _digest([canonical_id, environment])


def _observed_rows(job: Any, rows_for_job: RowsForJob) -> list[dict[str, Any]]:
    """The unified stream carries canonical identity; only legacy reports need the full projection."""
    stream = job.result.get("findings")
    rows = [row for row in stream if isinstance(row, dict)] if isinstance(stream, list) else []
    return rows or rows_for_job(job)


def _observation(row: dict[str, Any], project: str | None, at: str) -> tuple[str, Observation] | None:
    qualified = with_project_identity(row, project)
    identity = qualified.get("canonical_id")
    if not isinstance(identity, str) or not identity.strip():
        return None
    asset = qualified.get("asset")
    environment = str(qualified.get("environment") or (asset.get("environment") if isinstance(asset, dict) else None) or "")
    supplied = _normalized_evidence_timestamp(row.get("first_seen"))
    asset_key, coverage_key = asset_location(qualified)
    return finding_key(identity, environment), Observation(
        canonical_id=identity,
        environment=environment,
        report_canonical_id=qualified.get(REPORT_ID_FIELD),
        row=qualified,
        row_hash=_digest({name: value for name, value in row.items() if name not in _PER_SCAN_FIELDS}),
        first_seen=min(supplied, at) if supplied else at,
        asset_key=asset_key,
        coverage_key=coverage_key,
    )


def scan_evidence(job: Any, rows_for_job: RowsForJob) -> ScanEvidence | None:
    """What one finished leaf scan says, or ``None`` when it never executed."""
    if (
        job.status != JobStatus.DONE
        or not isinstance(job.result, dict)
        or job.child_job_ids
        or job.result.get("ingest_state")
        or not job_has_authoritative_scan_evidence(job)
    ):
        return None
    at = scan_evidence_authority_key(job)[0]
    project = finding_project_key(job)
    unscoped = scan_scope_key(job).startswith(_UNSCOPED_PUSH)
    observed: dict[str, Observation] = {}
    for row in _observed_rows(job, rows_for_job):
        built = _observation(row, project, at)
        if built is not None:
            observed.setdefault(*built)
    proves_absence = not scan_collection_incomplete_reasons(job)
    return ScanEvidence(
        tenant_id=str(getattr(job, "tenant_id", "default")),
        job_id=str(job.job_id),
        scope_hash=_track_scope(job, unscoped=unscoped),
        at=at,
        unscoped=unscoped,
        proves_absence=proves_absence,
        degraded=advisory_data_degraded(job),
        observed=observed,
        packages=_inventory_packages(job.result),
        proof=deletion_proof(job.result) if proves_absence else None,
    )


def _next_complete(complete_times: Sequence[str], after: str) -> str | None:
    index = bisect.bisect_right(complete_times, after)
    return complete_times[index] if index < len(complete_times) else None


def _new_state(key: str, seen: Observation, evidence: ScanEvidence, complete_times: Sequence[str]) -> FindingState:
    state = FindingState(
        scope_hash=evidence.scope_hash,
        finding_key=key,
        canonical_id=seen.canonical_id,
        environment=seen.environment,
        report_canonical_id=seen.report_canonical_id,
        first_seen=seen.first_seen,
        last_seen=evidence.at,
        last_job_id=evidence.job_id,
        asset_key=seen.asset_key,
        coverage_key=seen.coverage_key,
        payload_hash=seen.row_hash,
        new_row=seen.row,
        changed=True,
    )
    later = _next_complete(complete_times, evidence.at)
    if later is not None:
        state.resolve(later, REASON_NOT_DETECTED)
    return state


def _observe(state: FindingState, seen: Observation, evidence: ScanEvidence, complete_times: Sequence[str]) -> None:
    at = evidence.at
    prior_first_seen = state.first_seen
    state.first_seen = min(state.first_seen, seen.first_seen)
    state.scan_count += 1
    if at >= state.last_seen:
        state.last_seen, state.last_job_id = at, evidence.job_id
        state.asset_key, state.coverage_key = seen.asset_key, seen.coverage_key
        if seen.row_hash != state.payload_hash:
            state.payload_hash, state.new_row = seen.row_hash, seen.row
    if state.unconfirmed_at and at >= state.unconfirmed_at:
        state.unconfirmed_job_id, state.unconfirmed_at = None, None
    state.changed = True
    if at < prior_first_seen:
        _record_gap_before_first_sighting(state, at, prior_first_seen, complete_times)
    if state.live:
        if state.reopened_at and state.resolved_at and state.resolved_at < at < state.reopened_at:
            state.reopened_at = at
    elif at == state.resolved_at:
        state.status, state.resolved_at = ("reopened" if state.reopened_at else "open"), None
    elif at > (state.resolved_at or ""):
        state.reopened_at = at
        later = _next_complete(complete_times, at)
        if later is not None:
            state.resolved_at = later
        else:
            state.status = "reopened"


def _record_gap_before_first_sighting(state: FindingState, at: str, prior_first_seen: str, complete_times: Sequence[str]) -> None:
    """A late sighting earlier than a complete scan that predates the known run: the run was a reopen."""
    gap = _next_complete(complete_times, at)
    if gap is None or gap >= prior_first_seen:
        return
    state.reopened_at = state.reopened_at or prior_first_seen
    if state.live:
        state.status = "reopened"
    if (state.resolved_at or "") < gap:
        state.resolved_at = gap


def _absence_proves_fix(state: FindingState, evidence: ScanEvidence, load_payload: Callable[[FindingState], dict[str, Any]]) -> bool:
    """Without advisory data, absence proves a fix only when the package itself is gone."""
    if not evidence.degraded:
        return True
    name, version, _ = _package_identity(load_payload(state))
    if not name:
        return True
    return bool(evidence.packages) and (name.lower(), version) not in evidence.packages


def _absence_reason(state: FindingState, evidence: ScanEvidence) -> str | None:
    """Why this scan clears the finding; ``None`` when it cannot speak for it."""
    if not evidence.proves_absence:
        return None
    proof = evidence.proof
    placed = state.coverage_key is not None and proof is not None
    if placed and state.coverage_key not in proof.covered:  # type: ignore[union-attr]
        return None
    if placed and state.asset_key not in proof.present:  # type: ignore[union-attr]
        return REASON_ASSET_DELETED
    return None if evidence.unscoped else REASON_NOT_DETECTED


def _absent(state: FindingState, evidence: ScanEvidence, load_payload: Callable[[FindingState], dict[str, Any]]) -> None:
    reason = _absence_reason(state, evidence)
    if reason is None:
        return
    at = evidence.at
    if at <= state.last_seen:
        if state.live and state.first_seen < at < state.last_seen and (state.resolved_at or "") < at:
            state.resolved_at, state.resolution_reason, state.status = at, reason, "reopened"
            if (state.reopened_at or "") < at:
                state.reopened_at = state.last_seen
            state.changed = True
        return
    if not state.live:
        if at < (state.resolved_at or ""):
            state.resolved_at, state.resolution_reason, state.changed = at, reason, True
        return
    if _absence_proves_fix(state, evidence, load_payload):
        state.resolve(at, reason)
    else:
        state.unconfirmed_job_id, state.unconfirmed_at = evidence.job_id, at
    state.changed = True


def apply_evidence(
    states: dict[str, FindingState],
    evidence: ScanEvidence,
    complete_times: Sequence[str],
    load_payload: Callable[[FindingState], dict[str, Any]],
) -> list[FindingState]:
    """Fold one scan into its scope's states; returns those that changed.

    ``complete_times`` lists the scope's complete scans in order, including this
    one. A scan newer than everything can pass it empty, since nothing comes after.
    """
    for key, seen in evidence.observed.items():
        state = states.get(key)
        if state is None:
            states[key] = _new_state(key, seen, evidence, complete_times)
        else:
            _observe(state, seen, evidence, complete_times)
    for key, state in states.items():
        if key not in evidence.observed:
            _absent(state, evidence, load_payload)
    return [state for state in states.values() if state.changed]


def replay_lifecycle(jobs: Iterable[Any], rows_for_job: RowsForJob) -> list[FindingState]:
    """Fold retained scans in evidence order, for job stores with no durable table."""
    by_scope: dict[str, dict[str, FindingState]] = {}

    def own_payload(state: FindingState) -> dict[str, Any]:
        return state.new_row or {}

    built = (
        evidence for job in sorted(jobs, key=scan_evidence_authority_key) if (evidence := scan_evidence(job, rows_for_job)) is not None
    )
    for evidence in sorted(built, key=lambda item: item.at):
        states = by_scope.setdefault(evidence.scope_hash, {})
        apply_evidence(states, evidence, (), own_payload)
    return [state for states in by_scope.values() for state in states.values()]
