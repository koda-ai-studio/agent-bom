"""Regression coverage for large full-result scan responses."""

from __future__ import annotations

import json
from typing import cast

import pytest
from starlette.requests import Request

from agent_bom.api.models import ScanJob, ScanRequest


@pytest.mark.anyio
async def test_get_scan_offloads_full_result_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Full AI-BOM sanitization must not run on the server event-loop thread."""
    from agent_bom.api.routes import scan as scan_routes

    job = ScanJob(
        job_id="large-result",
        created_at="2026-08-28T00:00:00Z",
        request=ScanRequest(),
        result={"findings": [], "summary": {"total_findings": 0}},
    )
    offloaded: list[object] = []

    async def fake_load(_request: Request, _job_id: str) -> ScanJob:
        return job

    async def fake_run_sync(fn, *args):  # noqa: ANN001, ANN202
        offloaded.append(fn)
        return fn(*args)

    monkeypatch.setattr(scan_routes, "_load_job_for_request", fake_load)
    monkeypatch.setattr(scan_routes.anyio.to_thread, "run_sync", fake_run_sync)

    response = await scan_routes.get_scan(cast(Request, object()), job.job_id, view="full")

    assert json.loads(response.body)["job_id"] == job.job_id
    # Redaction and serialization of the full document run in one worker-thread call.
    assert offloaded == [scan_routes.full_body]
