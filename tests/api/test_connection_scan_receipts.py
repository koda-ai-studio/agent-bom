"""Worker completion must replace optimistic receipts with observed evidence."""

from types import SimpleNamespace

import pytest

from agent_bom.api import connection_scan_worker as worker
from agent_bom.api import managed_trial
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest


@pytest.mark.parametrize("status,expected", [("ok", ["aws:inventory"]), ("partial", [])])
def test_worker_persists_only_observed_capabilities(monkeypatch, status, expected):
    record = SimpleNamespace(
        id="conn-1",
        provider="aws",
        auth_params={},
        verified_capabilities=["bedrock:list-agents"],
    )
    reads = []
    marks = []

    def get(tenant_id, connection_id):
        reads.append((tenant_id, connection_id))
        return record

    monkeypatch.setattr(worker, "get_connection_store", lambda: SimpleNamespace(get=get))
    monkeypatch.setattr(managed_trial, "enforce_stored_connection_envelope", lambda record: None)
    monkeypatch.setattr(worker, "log_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker, "_mark_connection", lambda record, **kwargs: marks.append(kwargs))
    summary = {"inventory": {"status": status}}
    monkeypatch.setattr(worker, "_run_connection_scan", lambda *args, **kwargs: summary)
    job = ScanJob(
        job_id="scan-1",
        tenant_id="tenant-1",
        source_id="cloud-connection:conn-1",
        created_at="2026-10-22T00:00:00Z",
        request=ScanRequest(),
    )

    assert worker.execute_queued_connection_scan(job) == summary

    assert reads == [("tenant-1", "conn-1")]
    assert job.status == JobStatus.DONE
    assert marks[0]["verified_capabilities"] == expected
    assert marks[0]["capability_probe_status"] == ("verified" if expected else "unavailable")
    assert marks[0]["last_scan_id"] == "scan-1"
