"""``GET /v1/scan/{job_id}`` is summary-first; the full document is an explicit opt-in."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import patch

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.read_models.scan import ScanJobSummaryResponse
from agent_bom.api.scan_job_views import _job_response_payload
from tests.api.test_scan_result_sections import SECRET, _result
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401

TENANT = "detail-tenant"


def _put(status: JobStatus = JobStatus.DONE, job_id: str = "detail-job") -> ScanJob:
    from agent_bom.api.stores import _get_store

    result = None
    if status == JobStatus.DONE:
        result = _result()
        result["graph_persistence"] = {"status": "persisted", "scan_id": job_id, "nodes": 12, "edges": 30, "detail": SECRET}
    job = ScanJob(
        job_id=job_id,
        tenant_id=TENANT,
        status=status,
        created_at="2026-01-01T00:00:00Z",
        started_at="2026-01-01T00:00:01Z",
        completed_at="2026-01-01T00:01:00Z" if status == JobStatus.DONE else None,
        triggered_by="api",
        request=ScanRequest(),
        progress=[f"cloned with token {SECRET}", json.dumps({"type": "step", "step_id": "discovery", "message": f"key {SECRET}"})],
        result=result,
    )
    _get_store().put(job)
    return job


def _get(client, path: str, tenant: str = TENANT):
    return client.get(path, headers=proxy_headers(role="admin", tenant=tenant))


def test_default_read_is_a_bounded_summary_without_the_result(empty_estate_client) -> None:  # noqa: F811
    job = _put()
    response = _get(empty_estate_client, f"/v1/scan/{job.job_id}")
    assert response.status_code == 200, response.text
    body = response.json()
    parsed = ScanJobSummaryResponse.model_validate(body, strict=True, context={"strict_contract": True})
    assert parsed.model_dump(mode="json", exclude_unset=True) == body

    assert "result" not in body and "result_document" not in body
    assert body["view"] == "summary"
    assert body["status"] == "done"
    assert body["started_at"] == job.started_at
    assert body["result_format"] == "json"
    assert body["summary"] == job.result["summary"]
    assert body["scan_run"] == job.result.get("scan_run")
    assert body["graph_persistence"] == {"status": "persisted", "scan_id": job.job_id, "nodes": 12, "edges": 30}
    assert len(body["progress"]) == 2
    assert SECRET not in response.text

    index = _get(empty_estate_client, f"/v1/scan/{job.job_id}/result").json()
    assert body["result_sections"] == index["sections"]
    assert body["links"] == {
        "self": f"/v1/scan/{job.job_id}",
        "full": f"/v1/scan/{job.job_id}?view=full",
        "status": f"/v1/scan/{job.job_id}/status",
        "result": f"/v1/scan/{job.job_id}/result",
        "stream": f"/v1/scan/{job.job_id}/stream",
    }
    full = _get(empty_estate_client, f"/v1/scan/{job.job_id}?view=full")
    assert len(response.content) * 4 < len(full.content)


def test_full_view_keeps_the_scan_job_contract_and_redaction(empty_estate_client) -> None:  # noqa: F811
    job = _put()
    response = _get(empty_estate_client, f"/v1/scan/{job.job_id}?view=full")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body == json.loads(_job_response_payload(job).model_dump_json())
    assert body["result"]["summary"] == job.result["summary"]
    assert body["result_format"] == "json"
    assert SECRET not in response.text
    ScanJob.model_validate(body)


def test_summary_of_a_running_job_carries_progress_and_no_sections(empty_estate_client) -> None:  # noqa: F811
    job = _put(JobStatus.RUNNING, job_id="running-detail")
    body = _get(empty_estate_client, f"/v1/scan/{job.job_id}").json()
    ScanJobSummaryResponse.model_validate(body, strict=True, context={"strict_contract": True})
    assert body["status"] == "running"
    assert body["result_sections"] == []
    assert body["graph_persistence"] is None
    assert body["summary"] is None
    assert len(body["progress"]) == 2 and SECRET not in json.dumps(body)
    full = _get(empty_estate_client, f"/v1/scan/{job.job_id}?view=full").json()
    assert full["result"] is None and full["status"] == "running"


@pytest.mark.parametrize("view", ["", "?view=full"])
def test_both_views_are_tenant_scoped(empty_estate_client, view: str) -> None:  # noqa: F811
    _put()
    assert _get(empty_estate_client, f"/v1/scan/detail-job{view}", tenant="other-tenant").status_code == 404
    assert _get(empty_estate_client, f"/v1/scan/missing-job{view}").status_code == 404


@pytest.mark.parametrize("query", ["?view=everything", "?include=result", "?view=summary&full=1"])
def test_unknown_view_or_parameter_is_rejected(empty_estate_client, query: str) -> None:  # noqa: F811
    _put()
    assert _get(empty_estate_client, f"/v1/scan/detail-job{query}").status_code == 422


def test_openapi_documents_both_views() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    spec = app.openapi()
    operation = spec["paths"]["/v1/scan/{job_id}"]["get"]
    [view] = [param for param in operation["parameters"] if param["name"] == "view"]
    assert view["in"] == "query" and view["required"] is False
    assert set(view["schema"]["enum"]) == {"summary", "full"} and view["schema"]["default"] == "summary"
    schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    refs = {item["$ref"] for item in schema["anyOf"]}
    assert refs == {"#/components/schemas/ScanJobSummaryResponse", "#/components/schemas/ScanJob"}
    assert "ScanJobSummaryResponse" in spec["components"]["schemas"]


@pytest.mark.asyncio
async def test_full_view_redacts_and_serializes_off_the_event_loop() -> None:
    import httpx

    from agent_bom.api import scan_job_detail
    from agent_bom.api.server import app

    job = ScanJob(
        job_id="offload-full",
        tenant_id="default",
        status=JobStatus.DONE,
        created_at="2026-01-01T00:00:00Z",
        request=ScanRequest(),
        result={"findings": []},
    )
    real = scan_job_detail._job_response_payload
    ticks = 0

    def slow_payload(value: ScanJob) -> Any:
        time.sleep(0.4)
        return real(value)

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    with (
        patch("agent_bom.api.scan_request_context._job_for_request", return_value=job),
        patch.object(scan_job_detail, "_job_response_payload", side_effect=slow_payload),
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            beat = asyncio.create_task(heartbeat())
            await asyncio.sleep(0.02)
            before = ticks
            response = await client.get("/v1/scan/offload-full?view=full")
            observed = ticks - before
            beat.cancel()
    assert response.status_code == 200, response.text
    assert response.json()["job_id"] == "offload-full"
    assert observed >= 5, f"event loop advanced only {observed} tick(s) while the full result was serialized"
