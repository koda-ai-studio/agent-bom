"""API scan jobs and the MCP scan pipeline carry the same image evidence as the CLI."""

from __future__ import annotations

import shutil

import pytest

from agent_bom.oci_registry import client as registry_client
from tests._oci_image_builder import build_image, dpkg_status
from tests._oci_registry_fake import REGISTRY, FakeRegistry

REF = f"{REGISTRY}/team/api:2.0"
_AWS_KEY_ID = "AK" + "IA" + "Q3EGRT7ZXMPLW2NB"


@pytest.fixture
def registry(monkeypatch):
    fake = FakeRegistry()
    monkeypatch.setattr(registry_client, "_default_transport", fake.transport)
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    image = build_image(
        [{"var/lib/dpkg/status": dpkg_status(("bash", "5.2"))}, {"app/.env": f"AWS_ACCESS_KEY_ID={_AWS_KEY_ID}\n".encode()}]
    )
    fake.push_image("team/api", image, "2.0")
    fake.image = image  # type: ignore[attr-defined]
    return fake


def test_api_scan_job_reports_image_evidence_and_secret_findings(registry, monkeypatch):
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _run_scan_sync
    from agent_bom.api.store import InMemoryJobStore

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: InMemoryJobStore())
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("agent_bom.api.pipeline._persist_graph_snapshot", lambda *_args, **_kwargs: None)
    job = ScanJob(job_id="image-evidence", created_at="2026-10-26T00:00:00Z", request=ScanRequest(images=[REF], no_scan=True, enrich=False))

    _run_scan_sync(job)

    assert job.status == JobStatus.DONE, job.error
    [agent] = [a for a in job.result["agents"] if a["name"] == f"image:{REF}"]
    image = agent["metadata"]["image"]
    assert (image["source"], image["digest"], image["signature"]["status"]) == ("registry", registry.image.manifest_digest, "unsigned")
    secrets = [f for f in job.result["findings"] if f["evidence"].get("image") == REF]
    assert [f["evidence"]["layer_digest"] for f in secrets] == [registry.image.layer_digests[1]]
    assert _AWS_KEY_ID not in str(job.result)


@pytest.mark.asyncio
async def test_mcp_scan_pipeline_attaches_image_evidence(registry, monkeypatch):
    from agent_bom.mcp_server_scan import run_scan_pipeline

    async def scan(agents, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", scan)
    agents, _, warnings, sources = await run_scan_pipeline(safe_path=lambda value: value, image=REF, no_discover=True)

    assert sources == ["image"], warnings
    [agent] = agents
    assert agent.metadata["image"]["digest"] == registry.image.manifest_digest
    assert [s["layer_digest"] for s in agent.metadata["image"]["secrets"]] == [registry.image.layer_digests[1]]
