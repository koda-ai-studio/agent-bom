"""MCP ``intel_lookup`` reads the same tenant-scoped operator advisory store as REST."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.operator_advisory_store import InMemoryOperatorAdvisoryStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store, set_operator_advisory_store

ADVISORY = json.loads((Path(__file__).parents[1] / "fixtures" / "php2shell" / "operator-advisory.json").read_text())
TENANT = "tenant-mcp"


def _job(tenant: str) -> ScanJob:
    package = {"name": "php", "version": "8.3.30", "ecosystem": "generic", "cpe": "cpe:2.3:a:php:php:8.3.30:*:*:*:*:*:*:*"}
    return ScanJob(
        job_id=f"job-{tenant}",
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at="2026-10-20T00:01:00+00:00",
        completed_at="2026-10-20T00:01:00+00:00",
        request=ScanRequest(images=["php:8.3"]),
        result={"scan_id": f"scan-{tenant}", "agents": [{"name": "img", "mcp_servers": [{"name": "php", "packages": [package]}]}]},
    )


@pytest.fixture()
def configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))  # empty CLI-local advisory file
    jobs = InMemoryJobStore()
    for tenant in (TENANT, "tenant-other"):
        jobs.put(_job(tenant))
    set_job_store(jobs)
    store = InMemoryOperatorAdvisoryStore()
    set_operator_advisory_store(store)
    yield store
    set_operator_advisory_store(None)


def _lookup(monkeypatch: pytest.MonkeyPatch, tenant: str) -> dict:
    from agent_bom.mcp_tools.intel import intel_lookup_impl

    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", tenant)
    return json.loads(asyncio.run(intel_lookup_impl(advisory_id="CVE-2026-109618")))


def test_mcp_intel_lookup_returns_the_rest_declared_advisory_and_its_matches(configured, monkeypatch) -> None:
    from agent_bom.api.routes.operator_advisories import operator_advisory_matches

    configured.put(TENANT, ADVISORY)
    operator = _lookup(monkeypatch, TENANT)["operator_advisory"]
    assert operator["source"] == "tenant_store"
    assert operator["advisory"]["id"] == "CVE-2026-109618"
    assert [f["fixed_version"] for f in operator["matches"]["findings"]] == ["8.3.36"]
    assert operator["matches"] == operator_advisory_matches(TENANT, "CVE-2026-109618")
    assert operator["matches"]["tenant_id"] == TENANT


def test_mcp_intel_lookup_never_reads_another_tenants_advisory(configured, monkeypatch) -> None:
    configured.put("tenant-other", ADVISORY)
    assert "operator_advisory" not in _lookup(monkeypatch, TENANT)


def test_mcp_intel_lookup_keeps_the_local_file_without_a_configured_store(tmp_path, monkeypatch) -> None:
    from agent_bom.api import stores

    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    set_operator_advisory_store(None)
    assert stores.operator_advisory_store_configured() is False
