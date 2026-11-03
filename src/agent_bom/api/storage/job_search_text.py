"""Case-folded search text for in-memory job list filtering."""

from __future__ import annotations

import json
from typing import Any


def _job_search_text(job: Any) -> str:
    request_source = getattr(job.request, "source_id", None)
    values = (
        job.job_id,
        job.source_id,
        request_source,
        job.triggered_by,
        job.schedule_id,
        json.dumps(job.target, sort_keys=True) if job.target is not None else None,
    )
    return " ".join(str(value) for value in values if value).casefold()


def _job_summary_search_text(row: dict) -> str:
    values = (
        row.get("job_id"),
        row.get("source_id"),
        row.get("triggered_by"),
        row.get("schedule_id"),
        json.dumps(row.get("target"), sort_keys=True) if row.get("target") is not None else None,
    )
    return " ".join(str(value) for value in values if value).casefold()
