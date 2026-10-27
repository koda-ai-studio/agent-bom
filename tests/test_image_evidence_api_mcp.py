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


@pytest.mark.asyncio
async def test_mcp_keeps_image_evidence_without_packages(monkeypatch):
    from agent_bom.discovery.carriers import ImageScan, build_image_carrier
    from agent_bom.image_evidence.model import ImageEvidence
    from agent_bom.mcp_server_scan import run_scan_pipeline

    metadata = {"image": {"secrets": [{"type": "fixture", "preview": "[CREDENTIAL_REDACTED]"}]}}

    def scan_image(image, *, server_context):
        assert server_context is True
        return ImageScan(build_image_carrier(image, [], metadata=metadata), ImageEvidence(image), "registry")

    async def scan(agents, **kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", scan)
    monkeypatch.setattr("agent_bom.discovery.carriers.scan_image_carrier", scan_image)
    agents, _, _, sources = await run_scan_pipeline(safe_path=lambda value: value, image=REF, no_discover=True)
    assert sources == ["image"]
    assert len(agents) == 1
    assert agents[0].mcp_servers[0].packages == []
    assert agents[0].metadata["image"]["secrets"]


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_mcp_restores_image_worker_coverage(registry, monkeypatch, fail):
    from agent_bom.discovery import carriers
    from agent_bom.mcp_server_scan import run_scan_pipeline
    from agent_bom.scanners.state import consume_coverage_warnings, record_coverage_warning

    original = carriers.scan_image_carrier

    def scan_image(*args, **kwargs):
        record_coverage_warning({"release": REF, "reason": "oci_layer_download_failed"})
        if fail:
            raise RuntimeError("fixture image failure")
        return original(*args, **kwargs)

    async def scan(agents, **kwargs):
        return []

    monkeypatch.setattr(carriers, "scan_image_carrier", scan_image)
    monkeypatch.setattr("agent_bom.scanners.scan_agents", scan)
    await run_scan_pipeline(safe_path=lambda value: value, image=REF, no_discover=True)
    assert any(w["reason"] == "oci_layer_download_failed" for w in consume_coverage_warnings())


@pytest.mark.asyncio
async def test_mcp_tool_response_includes_image_worker_coverage(registry, monkeypatch):
    import json

    from mcp import Client

    from agent_bom.discovery import carriers
    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.scanners.state import record_coverage_warning, record_scan_warning

    original = carriers.scan_image_carrier

    def scan_image(*args, **kwargs):
        record_coverage_warning({"release": REF, "reason": "oci_layer_download_failed", "detail": "fixture gap"})
        record_scan_warning("fixture image warning")
        return original(*args, **kwargs)

    async def scan(agents, **kwargs):
        return []

    monkeypatch.setattr(carriers, "scan_image_carrier", scan_image)
    monkeypatch.setattr("agent_bom.scanners.scan_agents", scan)
    monkeypatch.setattr("agent_bom.graph.scan_findings.surface_graph_derived_findings", lambda *_args, **_kwargs: None)
    async with Client(create_mcp_server(profile="full")) as client:
        result = await client.call_tool("scan", {"image": REF, "no_discover": True})
    assert not result.is_error
    summary = json.loads(result.content[0].text)
    assert "fixture image warning" in summary["warnings"]
    assert any(w["reason"] == "oci_layer_download_failed" for w in summary["coverage_warnings"])
