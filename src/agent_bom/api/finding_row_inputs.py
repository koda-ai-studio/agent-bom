"""Fingerprint every non-job input of the scan-finding row rebuild, and when the clock changes it.

The rebuilt rows (:func:`agent_bom.api.scan_finding_read._current_scan_rows`
folded through :func:`agent_bom.api.findings_current.scan_only_findings`)
read, besides the job and hub evidence the walk cache already keys on:

* the tenant's exceptions: triage owners and suppressions;
* the runtime event index and the workload runtime index
  (:func:`agent_bom.api.scan_finding_projection.scan_row_sources`);
* the jobs the read window selects by completion time;
* the scan-snapshot read flags;
* the clock, through exceptions alone: one takes effect at ``approved_at``
  and lapses at ``expires_at``. SLA deadlines are absolute timestamps.

:func:`scan_row_inputs` digests all of them and returns the next wall-clock
instant (epoch seconds) at which the clock alone would change a row, so a cache
entry built from these rows expires exactly then.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from agent_bom.core.settings import env_raw
from agent_bom.core.timestamps import parse_timestamp

_FLAGS = ("AGENT_BOM_SCAN_SNAPSHOT_READS", "AGENT_BOM_SCAN_SNAPSHOT_FAST_READS")


def _plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: getattr(value, field.name) for field in dataclasses.fields(value) if not field.name.startswith("_")}
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items()}
    return str(value)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=_plain, separators=(",", ":")).encode()).hexdigest()


def clock_horizon(exceptions: Iterable[Any], now: datetime) -> float | None:
    """The earliest ``approved_at``/``expires_at`` after ``now``, in epoch seconds."""
    instants = []
    for exception in exceptions:
        for field in ("approved_at", "expires_at"):
            moment = parse_timestamp(getattr(exception, field, None))
            if moment is not None and moment > now:
                instants.append(moment.timestamp())
    return min(instants, default=None)


def scan_row_inputs(
    tenant_id: str, *, sources: Mapping[str, Any], window_job_ids: Iterable[str], now: datetime | None = None
) -> tuple[tuple[str, ...], float | None]:
    """``(fingerprint, horizon)`` for the rows ``sources`` and the windowed jobs produce."""
    exceptions = list(sources.get("exceptions") or [])
    fingerprint = (
        tenant_id,
        _digest([_plain(exception) for exception in exceptions]),
        _digest(sources.get("runtime_events")),
        _digest(sources.get("workload_runtime")),
        _digest(sorted(window_job_ids)),
        _digest([env_raw(flag) or "" for flag in _FLAGS]),
    )
    return fingerprint, clock_horizon(exceptions, now or datetime.now(timezone.utc))


__all__ = ["clock_horizon", "scan_row_inputs"]
