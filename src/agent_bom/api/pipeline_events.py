"""Api pipeline events helpers."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom.api.models import ScanJob, StepStatus
from agent_bom.security import sanitize_sensitive_payload

# ─── Constants ───────────────────────────────────────────────────────────────

PIPELINE_STEPS = ["discovery", "extraction", "scanning", "enrichment", "analysis", "output"]

PIPELINE_DAG_EVENT_SCHEMA = "agent-bom.pipeline.dag.events.v1"

PIPELINE_DAG_EDGES = [{"source": source, "target": target} for source, target in zip(PIPELINE_STEPS, PIPELINE_STEPS[1:], strict=False)]

_PIPELINE_STEP_INDEX = {step_id: index for index, step_id in enumerate(PIPELINE_STEPS)}

_PIPELINE_PREDECESSORS = {
    step_id: [edge["source"] for edge in PIPELINE_DAG_EDGES if edge["target"] == step_id] for step_id in PIPELINE_STEPS
}

_PIPELINE_SUCCESSORS = {step_id: [edge["target"] for edge in PIPELINE_DAG_EDGES if edge["source"] == step_id] for step_id in PIPELINE_STEPS}

_TERMINAL_STEP_STATUSES = {
    StepStatus.DONE.value,
    StepStatus.FAILED.value,
    StepStatus.SKIPPED.value,
}

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def iter_pipeline_dag_event_records(
    progress_lines: Iterable[str],
    *,
    scan_id: str,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return dashboard-ready DAG step records from structured progress lines.

    The API already emits JSON step progress records for SSE consumers. This
    helper keeps that wire behavior intact while giving local tests, report
    exporters, and dashboards a stable JSONL artifact shape that includes the
    scan pipeline DAG edges needed to render progress as a graph.
    """
    records: list[dict[str, Any]] = []
    for sequence, line in enumerate(progress_lines):
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, dict) or event.get("type") != "step":
            continue
        step_id = event.get("step_id")
        status = event.get("status")
        if not isinstance(step_id, str) or step_id not in _PIPELINE_STEP_INDEX:
            continue
        if isinstance(status, StepStatus):
            status = status.value
        if not isinstance(status, str):
            continue

        emitted_at = event.get("completed_at") or event.get("started_at")
        record: dict[str, Any] = {
            "schema_version": PIPELINE_DAG_EVENT_SCHEMA,
            "type": "pipeline_dag_step",
            "event_id": f"{scan_id}:{sequence}:{step_id}:{status}",
            "scan_id": scan_id,
            "sequence": sequence,
            "emitted_at": emitted_at if isinstance(emitted_at, str) else None,
            "step": {
                "id": step_id,
                "index": _PIPELINE_STEP_INDEX[step_id],
                "status": status,
                "message": event.get("message") if isinstance(event.get("message"), str) else "",
                "started_at": event.get("started_at") if isinstance(event.get("started_at"), str) else None,
                "completed_at": event.get("completed_at") if isinstance(event.get("completed_at"), str) else None,
                "stats": event.get("stats") if isinstance(event.get("stats"), dict) else {},
                "sub_step": event.get("sub_step") if isinstance(event.get("sub_step"), str) else None,
                "progress_pct": event.get("progress_pct") if isinstance(event.get("progress_pct"), int) else None,
            },
            "dag": {
                "node_id": step_id,
                "depends_on": list(_PIPELINE_PREDECESSORS[step_id]),
                "next_steps": list(_PIPELINE_SUCCESSORS[step_id]),
                "edges": [dict(edge) for edge in PIPELINE_DAG_EDGES],
            },
            "dashboard": {
                "lane": "scan_pipeline",
                "render": "dag_step",
                "terminal": status in _TERMINAL_STEP_STATUSES,
            },
        }
        if tenant_id:
            record["tenant_id"] = tenant_id
        records.append(record)
    return records


def pipeline_dag_events_jsonl(job: ScanJob) -> str:
    """Serialize a scan job's structured pipeline events as JSONL."""
    records = iter_pipeline_dag_event_records(
        list(job.progress),
        scan_id=job.job_id,
        tenant_id=job.tenant_id,
    )
    return "\n".join(json.dumps(record, sort_keys=True) for record in records)


# ─── ScanPipeline ────────────────────────────────────────────────────────────


class ScanPipeline:
    """Track scan pipeline steps and emit structured events to job.progress."""

    def __init__(self, job: ScanJob, lock: threading.Lock | None = None) -> None:
        self._job = job
        self._lock = lock
        self._steps: dict[str, dict[str, Any]] = {}
        for step_id in PIPELINE_STEPS:
            self._steps[step_id] = {
                "type": "step",
                "step_id": step_id,
                "status": StepStatus.PENDING,
                "message": f"Pending: {step_id}",
                "started_at": None,
                "completed_at": None,
                "stats": {},
                "sub_step": None,
                "progress_pct": None,
            }

    def start_step(self, step_id: str, message: str, sub_step: str | None = None) -> None:
        """Mark a step as running and emit event."""
        event = self._steps[step_id]
        event["status"] = StepStatus.RUNNING
        event["message"] = message
        event["started_at"] = _now()
        event["sub_step"] = sub_step
        self._emit(event)

    def update_step(
        self,
        step_id: str,
        message: str,
        stats: dict[str, Any] | None = None,
        progress_pct: int | None = None,
    ) -> None:
        """Update a running step with new message/stats."""
        event = self._steps[step_id]
        event["message"] = message
        if stats:
            event["stats"].update(stats)
        if progress_pct is not None:
            event["progress_pct"] = progress_pct
        self._emit(event)

    def complete_step(self, step_id: str, message: str, stats: dict[str, Any] | None = None) -> None:
        """Mark a step as done."""
        event = self._steps[step_id]
        event["status"] = StepStatus.DONE
        event["message"] = message
        event["completed_at"] = _now()
        if stats:
            event["stats"].update(stats)
        self._emit(event)

    def fail_step(self, step_id: str, message: str) -> None:
        """Mark a step as failed."""
        event = self._steps[step_id]
        event["status"] = StepStatus.FAILED
        event["message"] = message
        event["completed_at"] = _now()
        self._emit(event)

    def skip_step(self, step_id: str, message: str) -> None:
        """Mark a step as skipped."""
        event = self._steps[step_id]
        event["status"] = StepStatus.SKIPPED
        event["message"] = message
        event["completed_at"] = _now()
        self._emit(event)

    def _emit(self, event: dict[str, Any]) -> None:
        """Serialize step event to job.progress for SSE pickup (thread-safe)."""
        # Convert enum values to strings for JSON serialization
        serializable = {k: (v.value if isinstance(v, Enum) else v) for k, v in event.items()}
        line = json.dumps(sanitize_sensitive_payload(serializable))
        if self._lock:
            with self._lock:
                self._job.progress.append(line)
        else:
            self._job.progress.append(line)
