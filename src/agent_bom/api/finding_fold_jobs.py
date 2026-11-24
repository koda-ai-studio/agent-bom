"""Decode and project each committed scan once per row version for the findings fold.

Rebuilding the current findings after any job write decoded every retained
report and projected all of its findings again, so one new scan cost as much as
all retained history and every reader waited for it. A job store that reports a
version per committed row (:meth:`PostgresJobStore.done_job_versions`) lets the
fold decode only rows it has not seen at that version.

Each digest keeps the job with its result trimmed to :data:`FOLD_RESULT_KEYS`
(what job selection and retained history read) and the job's projected rows.
Projected rows also read tenant-wide inputs; a digest serves only the row-input
fingerprint it was built under and only before that fingerprint's clock
horizon. Digests and their rows are shared across requests and read-only.

Stores without row versions, and the opt-in snapshot read modes (which read
other stores per job), keep the full decode. ``AGENT_BOM_FINDING_WALK_CACHE=0``
turns this off with the rest of the cross-request finding reuse.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_bom.api.finding_row_inputs import history_ledger_reads_enabled
from agent_bom.api.finding_walk_cache import reuse_enabled
from agent_bom.api.models import JobStatus, ScanJob

#: Result keys the fold reads besides the projected rows: selection, scope, coverage and retained history.
FOLD_RESULT_KEYS = frozenset(
    {
        "dry_run",
        "findings",
        "generated_at",
        "no_scan",
        "pushed",
        "scan_id",
        "scan_run",
        "scan_scope",
        "scan_skipped",
        "scan_sources",
        "scan_timestamp",
        "source_scope",
        "target_scope",
    }
)
#: Row fields retained history reads: the occurrence key and the dates and deadline it carries forward.
HISTORY_ROW_KEYS = frozenset(
    {
        "report_canonical_id",
        "canonical_id",
        "environment",
        "first_seen",
        "sla_due_at",
        "sla_due_at_source",
        "kev_due_date",
        "effective_severity",
        "severity",
    }
)
#: Upper bound on retained-history plus projected rows held across all digests in a process.
MAX_DIGEST_ROWS = 400_000


@dataclass
class _Digest:
    """A completed scan as the fold reads it; ``rows`` is projected only once the fold selects the scan."""

    job: ScanJob
    size: int
    rows: list[dict[str, Any]] | None = None
    inputs: tuple[Any, ...] | None = None
    horizon: float | None = None


_LOCK = threading.Lock()
_DIGESTS: OrderedDict[str, _Digest] = OrderedDict()
_held = 0
Projection = Callable[[ScanJob], list[dict[str, Any]]]


def clear() -> None:
    global _held
    with _LOCK:
        _DIGESTS.clear()
        _held = 0


def _rows_fresh(digest: _Digest, inputs: tuple[Any, ...]) -> bool:
    return digest.rows is not None and digest.inputs == inputs and (digest.horizon is None or time.time() < digest.horizon)


def _resize(version: str, digest: _Digest, size: int) -> None:
    """Account ``digest`` at ``size`` rows and evict the least recently used past the bound."""
    global _held
    with _LOCK:
        previous = _DIGESTS.pop(version, None)
        if previous is not None:
            _held -= previous.size
        if size > MAX_DIGEST_ROWS:
            return
        digest.size = size
        _DIGESTS[version] = digest
        _held += size
        while _held > MAX_DIGEST_ROWS:
            _, evicted = _DIGESTS.popitem(last=False)
            _held -= evicted.size


def _history_row(row: Any) -> Any:
    """Only what retained history reads: identity, environment, first sighting, deadline and KEV date."""
    if not isinstance(row, dict):
        return row
    kept = {key: row[key] for key in HISTORY_ROW_KEYS if key in row}
    asset, evidence = row.get("asset"), row.get("evidence")
    if isinstance(asset, dict) and "environment" in asset:
        kept["asset"] = {"environment": asset["environment"]}
    if isinstance(evidence, dict) and "kev_due_date" in evidence:
        kept["evidence"] = {"kev_due_date": evidence["kev_due_date"]}
    return kept


def _slim(job: ScanJob) -> tuple[ScanJob, int]:
    result = job.result or {}
    kept = {key: result[key] for key in FOLD_RESULT_KEYS if key in result}
    findings = kept.get("findings")
    if isinstance(findings, list):
        kept["findings"] = [_history_row(row) for row in findings]
    return job.model_copy(update={"result": kept}), len(findings) if isinstance(findings, list) else 0


def fold_jobs(
    tenant_id: str, store: Any, inputs: tuple[tuple[Any, ...], float | None], project: Projection
) -> tuple[list[ScanJob], Projection] | None:
    """Completed jobs for the fold, newest first, and their projected rows; ``None`` to decode in full.

    Every completed scan is decoded once per row version into a slim digest. Rows
    are projected only for the scans the fold asks for (the current snapshot per
    scope), reusing a job decoded in this call or reloading just that one.
    """
    list_versions = getattr(store, "done_job_versions", None)
    load = getattr(store, "jobs_with_versions", None)
    if not callable(list_versions) or not callable(load) or not reuse_enabled() or history_ledger_reads_enabled():
        return None
    fingerprint, horizon = inputs
    versions = list_versions(tenant_id)
    held: dict[str, tuple[str, _Digest]] = {}
    with _LOCK:
        for job_id, version in versions:
            if (digest := _DIGESTS.get(version)) is not None:
                _DIGESTS.move_to_end(version)
                held[job_id] = (version, digest)
    decoded: dict[str, ScanJob] = {}

    def keep(version: str, job: ScanJob) -> None:
        if job.status != JobStatus.DONE or not job.result:
            return
        slim, history = _slim(job)
        digest = _Digest(slim, history)
        decoded[job.job_id] = job
        held[job.job_id] = (version, digest)
        _resize(version, digest, history)

    missing = [job_id for job_id, _ in versions if job_id not in held]
    for version, job in load(tenant_id, missing) if missing else ():
        keep(version, job)
    ordered = [held[job_id] for job_id, _ in versions if job_id in held]
    by_slim = {id(digest.job): (version, digest) for version, digest in ordered}

    def rows_for(slim: ScanJob) -> list[dict[str, Any]]:
        version, digest = by_slim[id(slim)]
        if _rows_fresh(digest, fingerprint):
            return digest.rows or []
        full = decoded.get(slim.job_id)
        if full is None:
            reloaded = [job for _, job in load(tenant_id, [slim.job_id]) if job.job_id == slim.job_id]
            if not reloaded:  # deleted since it was listed
                return []
            full = reloaded[0]
        history = digest.size - len(digest.rows or [])
        rows = project(full)
        digest.rows, digest.inputs, digest.horizon = rows, fingerprint, horizon
        _resize(version, digest, history + len(rows))
        return rows

    return [digest.job for _, digest in ordered], rows_for


__all__ = ["FOLD_RESULT_KEYS", "MAX_DIGEST_ROWS", "clear", "fold_jobs"]
