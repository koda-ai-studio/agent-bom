"""Graph export formats are validated, not silently replaced by JSON."""

from __future__ import annotations

import json

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from tests.api.test_api_endpoints import _fresh_client


def test_graph_export_rejects_an_unknown_format_with_the_valid_list():
    """An unknown format is a client error, not a silent JSON 200."""
    client, store = _fresh_client()
    store.put(
        ScanJob(
            job_id="job-graph-format",
            status=JobStatus.DONE,
            created_at="2026-05-20T00:00:00Z",
            completed_at="2026-05-20T00:00:01Z",
            request=ScanRequest(),
            result={"agents": [{"name": "claude-desktop", "agent_type": "claude-desktop", "mcp_servers": []}]},
        )
    )

    response = client.get("/v1/scan/job-graph-format/graph-export?format=bogus")

    assert response.status_code == 422, response.text
    detail = json.dumps(response.json())
    for valid in ("json", "dot", "mermaid", "graphml", "cypher"):
        assert valid in detail
    assert client.get("/v1/scan/job-graph-format/graph-export?format=json").status_code == 200
