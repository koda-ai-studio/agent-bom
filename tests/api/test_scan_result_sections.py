"""Sectioned scan-result reads match the full result, and the full read stays off the event loop."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.read_models.scan import ScanResultIndexResponse, ScanResultSectionResponse
from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport, BlastRadius, MCPServer, MCPTool, Package, Severity, Vulnerability
from agent_bom.output import to_json
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401

TENANT = "sections-tenant"
SECRET = "ghp_" + "c" * 36


def _result() -> dict:
    tool = MCPTool(name="deploy", description=f"uses {SECRET}")
    server = MCPServer(name="mcp", command="npx", args=["mcp"], tools=[tool], env={"API_TOKEN": "x"})
    agent = Agent(
        name="assistant",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/a.json",
        mcp_servers=[server],
        status=AgentStatus.CONFIGURED,
    )
    radii = []
    for index in range(5):
        pkg = Package(name=f"lib{index}", version="1.0.0", ecosystem="npm")
        server.packages.append(pkg)
        vuln = Vulnerability(id=f"CVE-2024-{index:04d}", severity=Severity.HIGH, summary=f"leak {SECRET}", cvss_score=8.1)
        radii.append(
            BlastRadius(
                package=pkg,
                vulnerability=vuln,
                affected_agents=[agent],
                affected_servers=[server],
                exposed_credentials=["API_TOKEN"],
                exposed_tools=[tool],
            )
        )
    return to_json(AIBOMReport(agents=[agent], blast_radii=radii, generated_at=datetime(2026, 1, 1), tool_version="0.0.0"))


def _put(status: JobStatus = JobStatus.DONE, job_id: str = "sections-job") -> ScanJob:
    from agent_bom.api.stores import _get_store

    job = ScanJob(
        job_id=job_id,
        tenant_id=TENANT,
        status=status,
        created_at="2026-01-01T00:00:00Z",
        request=ScanRequest(),
        result=_result() if status == JobStatus.DONE else None,
    )
    _get_store().put(job)
    return job


def _get(client, path: str, tenant: str = TENANT, **headers):
    return client.get(path, headers={**proxy_headers(role="admin", tenant=tenant), **headers})


def test_index_lists_every_large_section_with_counts(empty_estate_client) -> None:  # noqa: F811
    job = _put()
    response = _get(empty_estate_client, f"/v1/scan/{job.job_id}/result")
    assert response.status_code == 200, response.text
    body = response.json()
    ScanResultIndexResponse.model_validate(body)
    sections = {row["name"]: row for row in body["sections"]}
    assert sections["findings"]["kind"] == "list" and sections["findings"]["count"] == len(job.result["findings"])
    assert sections["blast_radius"]["count"] == 5
    assert sections["exposure_paths"]["kind"] == "object" and sections["exposure_paths"]["count"] is None
    assert sections["findings"]["href"] == f"/v1/scan/{job.job_id}/result/findings?offset=0&limit=100"
    assert body["summary"]["summary"] == job.result["summary"]
    assert set(sections).isdisjoint(body["summary"])
    assert set(sections) | set(body["summary"]) == set(job.result)
    assert len(response.content) * 4 < len(json.dumps(job.result))


def test_paging_every_section_reproduces_the_full_redacted_result(empty_estate_client) -> None:  # noqa: F811
    job = _put()
    full = _get(empty_estate_client, f"/v1/scan/{job.job_id}").json()["result"]
    assert SECRET not in json.dumps(full)
    index = _get(empty_estate_client, f"/v1/scan/{job.job_id}/result").json()
    rebuilt = dict(index["summary"])
    for section in index["sections"]:
        if section["kind"] == "object":
            page = _get(empty_estate_client, section["href"]).json()
            ScanResultSectionResponse.model_validate(page)
            rebuilt[section["name"]] = page["value"]
            continue
        items, offset = [], 0
        while offset is not None:
            page = _get(empty_estate_client, f"/v1/scan/{job.job_id}/result/{section['name']}?offset={offset}&limit=2").json()
            ScanResultSectionResponse.model_validate(page)
            assert page["total"] == section["count"]
            items.extend(page["items"])
            offset = page["next_offset"]
        rebuilt[section["name"]] = items
    assert rebuilt == full


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/v1/scan/sections-job/result/summary", 404),
        ("/v1/scan/sections-job/result/no-such-section", 404),
        ("/v1/scan/sections-job/result/findings?limit=0", 422),
        ("/v1/scan/sections-job/result/findings?limit=1001", 422),
        ("/v1/scan/sections-job/result/findings?offset=-1", 422),
    ],
)
def test_section_reads_reject_bad_requests(empty_estate_client, path: str, status: int) -> None:  # noqa: F811
    _put()
    assert _get(empty_estate_client, path).status_code == status


def test_sections_are_tenant_scoped_and_wait_for_completion(empty_estate_client) -> None:  # noqa: F811
    _put()
    assert _get(empty_estate_client, "/v1/scan/sections-job/result", tenant="other-tenant").status_code == 404
    _put(JobStatus.RUNNING, job_id="running-job")
    assert _get(empty_estate_client, "/v1/scan/running-job/result").status_code == 409
    assert _get(empty_estate_client, "/v1/scan/running-job/result/findings").status_code == 409


def test_full_result_is_rendered_off_the_event_loop_and_unchanged(empty_estate_client, monkeypatch) -> None:  # noqa: F811
    from agent_bom.api.routes import scan as scan_routes
    from agent_bom.api.scan_job_views import _job_response_payload

    job = _put()
    render = scan_routes._render_job_response
    loops: list[bool] = []

    def spy(value: ScanJob) -> bytes:
        try:
            asyncio.get_running_loop()
            loops.append(True)
        except RuntimeError:
            loops.append(False)
        return render(value)

    monkeypatch.setattr(scan_routes, "_render_job_response", spy)
    response = _get(empty_estate_client, f"/v1/scan/{job.job_id}", **{"Accept-Encoding": "gzip"})
    assert response.status_code == 200
    assert loops == [False]
    assert response.headers["content-type"] == "application/json"
    assert response.headers.get("content-encoding") == "gzip"
    assert response.json() == json.loads(_job_response_payload(job).model_dump_json())
    assert ScanJob.model_validate(response.json()).result == response.json()["result"]


def test_large_responses_are_gzipped_in_a_worker_thread() -> None:
    from starlette.middleware.gzip import GZipMiddleware

    from agent_bom.api.server import app

    [gzip] = [m for m in app.user_middleware if m.cls is GZipMiddleware]
    assert gzip.kwargs["thread_minimum_size"] <= 128 * 1024
