"""Perf budget: the default ``GET /v1/scan/{job_id}`` stays bounded however large the result is."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401

TENANT = "perf-budget"
SUMMARY_BUDGET_BYTES = 1_000_000
MIN_RESULT_BYTES = 50_000_000


def _large_result(findings: int = 60_000) -> dict:
    return {
        "document_type": "AI-BOM",
        "scan_id": "perf-job",
        "summary": {"total_findings": findings, "total_packages": 997},
        "scan_run": {"outcome": "complete", "warning_count": 0},
        "graph_persistence": {"status": "persisted", "scan_id": "perf-job", "nodes": 10, "edges": 20},
        "findings": [
            {
                "id": f"finding-{i}",
                "severity": "high",
                "title": f"CVE-2026-{i:06d} in package-{i % 997}",
                "description": f"Synthetic advisory {i} " + "detail " * 100,
                "references": [f"https://example.invalid/advisory/{i}/{j}" for j in range(4)],
            }
            for i in range(findings)
        ],
    }


def test_default_read_of_a_large_job_is_bounded_and_never_decodes_the_result(empty_estate_client, tmp_path: Path) -> None:  # noqa: F811
    from agent_bom.api import stores as api_stores
    from agent_bom.api.store import SQLiteJobStore

    result = _large_result()
    assert len(json.dumps(result)) >= MIN_RESULT_BYTES
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    store.put(
        ScanJob(
            job_id="perf-job",
            tenant_id=TENANT,
            status=JobStatus.DONE,
            created_at="2026-11-01T00:00:00Z",
            request=ScanRequest(),
            result=result,
        )
    )
    del result
    original = api_stores._store
    api_stores._store = store
    headers = proxy_headers(role="admin", tenant=TENANT)
    try:
        with patch("agent_bom.api.job_payload_codec.decode_zstd_json", side_effect=AssertionError("summary decoded the result")):
            started = time.perf_counter()
            summary = empty_estate_client.get("/v1/scan/perf-job", headers=headers)
            elapsed = time.perf_counter() - started
        assert summary.status_code == 200, summary.text
        assert len(summary.content) <= SUMMARY_BUDGET_BYTES
        body = summary.json()
        assert "result" not in body and body["summary"]["total_findings"] == 60_000
        assert any(section["name"] == "findings" and section["count"] == 60_000 for section in body["result_sections"])
        assert elapsed < 5, f"default read took {elapsed:.2f}s"

        full = empty_estate_client.get(body["links"]["full"], headers=headers)
        assert full.status_code == 200
        assert len(full.json()["result"]["findings"]) == 60_000
    finally:
        api_stores._store = original
