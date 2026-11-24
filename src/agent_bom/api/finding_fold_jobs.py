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
#: Upper bound on projected plus retained-history rows held across all digests in a process.
MAX_DIGEST_ROWS = 400_000


@dataclass(frozen=True)
class _Digest:
    job: ScanJob
    inputs: tuple[Any, ...]
    horizon: float | None
    rows: list[dict[str, Any]]
    size: int


_LOCK = threading.Lock()
_DIGESTS: OrderedDict[str, _Digest] = OrderedDict()
_held = 0
Projection = Callable[[ScanJob], list[dict[str, Any]]]


def clear() -> None:
    global _held
    with _LOCK:
        _DIGESTS.clear()
        _held = 0


def _fresh(digest: _Digest, inputs: tuple[Any, ...]) -> bool:
    return digest.inputs == inputs and (digest.horizon is None or time.time() < digest.horizon)


def _keep(version: str, digest: _Digest) -> None:
    global _held
    if digest.size > MAX_DIGEST_ROWS:
        return
    with _LOCK:
        previous = _DIGESTS.pop(version, None)
        if previous is not None:
            _held -= previous.size
        _DIGESTS[version] = digest
        _held += digest.size
        while _held > MAX_DIGEST_ROWS:
            _, evicted = _DIGESTS.popitem(last=False)
            _held -= evicted.size


def _digest(job: ScanJob, inputs: tuple[Any, ...], horizon: float | None, project: Projection) -> _Digest:
    rows = project(job)
    result = job.result or {}
    slim = job.model_copy(update={"result": {key: result[key] for key in FOLD_RESULT_KEYS if key in result}})
    retained = result.get("findings")
    size = len(rows) + (len(retained) if isinstance(retained, list) else 0)
    return _Digest(slim, inputs, horizon, rows, size)


def fold_jobs(
    tenant_id: str, store: Any, inputs: tuple[tuple[Any, ...], float | None], project: Projection
) -> tuple[list[ScanJob], Projection] | None:
    """Completed jobs for the fold, newest first, and their projected rows; ``None`` to decode in full."""
    list_versions = getattr(store, "done_job_versions", None)
    load = getattr(store, "jobs_with_versions", None)
    if not callable(list_versions) or not callable(load) or not reuse_enabled() or history_ledger_reads_enabled():
        return None
    fingerprint, horizon = inputs
    versions = list_versions(tenant_id)
    held: dict[str, _Digest] = {}
    with _LOCK:
        for job_id, version in versions:
            digest = _DIGESTS.get(version)
            if digest is not None and _fresh(digest, fingerprint):
                _DIGESTS.move_to_end(version)
                held[job_id] = digest
    missing = [job_id for job_id, _ in versions if job_id not in held]
    for version, job in load(tenant_id, missing) if missing else ():
        if job.status != JobStatus.DONE or not job.result:
            continue
        digest = _digest(job, fingerprint, horizon, project)
        held[job.job_id] = digest
        _keep(version, digest)
    ordered = [held[job_id] for job_id, _ in versions if job_id in held]
    rows = {id(digest.job): digest.rows for digest in ordered}
    return [digest.job for digest in ordered], lambda job: rows[id(job)]


__all__ = ["FOLD_RESULT_KEYS", "MAX_DIGEST_ROWS", "clear", "fold_jobs"]
