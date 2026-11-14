"""``GET /v1/scan/{job_id}?view=full`` streams a large job instead of building the whole body at once.

At 5,000 agents the full job was an 18 MB response encoded into one buffer.
The streamed body must be byte-identical to the one-shot body (same contract,
same redaction), and encoding it must not hold a body-sized buffer.
"""

from __future__ import annotations

import json
import tracemalloc
from typing import Any

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.scan_full_stream import full_body_chunks, streams_full_body
from agent_bom.api.scan_job_detail import full_body
from tests.api.test_scan_result_sections import SECRET
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401

TENANT = "full-stream-tenant"


def _agent(i: int) -> dict[str, Any]:
    return {
        "name": f"agent-{i}",
        "agent_type": "cursor",
        "config_path": f"/srv/fleet/{i}/mcp.json",
        "mcp_servers": [
            {
                "name": f"srv-{i}-{j}",
                "command": "npx",
                "env": {"API_KEY": SECRET} if i == 7 and j == 0 else {},
                "packages": [{"name": f"pkg-{(i + j) % 300}", "version": "1.0.0", "ecosystem": "npm", "score": 1.5, "note": "café ☃"}],
            }
            for j in range(2)
        ],
    }


def _wide_result(agents: int) -> dict[str, Any]:
    return {
        "document_type": "AI-BOM",
        "schema_version": "1.0",
        "summary": {"total_agents": agents, "total_findings": agents},
        "agents": [_agent(i) for i in range(agents)],
        "findings": [{"id": f"f-{i}", "severity": "high", "asset": {"name": f"agent-{i}"}, "evidence": None} for i in range(agents)],
        "blast_radius": [],
        "empty": {},
        "ratio": 0.25,
    }


def _job(agents: int, job_id: str = "full-stream-job") -> ScanJob:
    return ScanJob(
        job_id=job_id,
        tenant_id=TENANT,
        status=JobStatus.DONE,
        created_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:01:00Z",
        triggered_by="api",
        request=ScanRequest(),
        progress=[f"cloned with token {SECRET}", "done"],
        result=_wide_result(agents),
    )


def test_streamed_body_is_byte_identical_to_the_one_shot_body() -> None:
    for agents in (0, 3, 600):
        job = _job(agents)
        assert b"".join(full_body_chunks(job)) == full_body(job)
    running = ScanJob(job_id="r", tenant_id=TENANT, created_at="2026-01-01T00:00:00Z", request=ScanRequest())
    assert b"".join(full_body_chunks(running)) == full_body(running)


def test_only_large_jobs_stream() -> None:
    assert not streams_full_body(_job(3))
    assert streams_full_body(_job(5_000))


def _peak(produce) -> int:
    tracemalloc.start()
    try:
        baseline, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        produce()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak - baseline


def test_streaming_a_5000_agent_job_never_holds_a_body_sized_buffer() -> None:
    job = _job(5_000)
    body_size = len(full_body(job))
    sizes: list[int] = []
    streamed_peak = _peak(lambda: sizes.extend(len(chunk) for chunk in full_body_chunks(job)))
    one_shot_peak = _peak(lambda: full_body(job))
    assert sum(sizes) == body_size
    assert max(sizes) <= 256 * 1024
    # Both build the redacted result copy; only the one-shot path also holds the encoded body.
    assert streamed_peak + body_size * 0.8 <= one_shot_peak, f"streamed {streamed_peak:,} vs one-shot {one_shot_peak:,}"


def test_route_streams_a_large_full_view_with_the_same_json(empty_estate_client) -> None:  # noqa: F811
    from agent_bom.api.stores import _get_store

    job = _job(5_000, job_id="full-stream-route")
    _get_store().put(job)
    response = empty_estate_client.get(f"/v1/scan/{job.job_id}?view=full", headers=proxy_headers(role="admin", tenant=TENANT))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/json"
    assert "content-length" not in response.headers
    body = response.json()
    assert body["job_id"] == job.job_id
    assert len(body["result"]["agents"]) == 5_000
    assert body["result"]["agents"][4_999]["name"] == "agent-4999"
    assert SECRET not in response.text
    assert json.loads(full_body(job)) == body


def test_route_keeps_a_small_full_view_in_one_body(empty_estate_client) -> None:  # noqa: F811
    from agent_bom.api.stores import _get_store

    job = _job(3, job_id="full-stream-small")
    _get_store().put(job)
    response = empty_estate_client.get(f"/v1/scan/{job.job_id}?view=full", headers=proxy_headers(role="admin", tenant=TENANT))
    assert response.status_code == 200, response.text
    assert "content-length" in response.headers
    assert len(response.json()["result"]["agents"]) == 3
