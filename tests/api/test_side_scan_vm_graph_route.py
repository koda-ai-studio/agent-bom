"""POST /v1/cloud/side-scan returns packages/CVEs per VM and persists them to the graph.

The executor is faked at the module seam (no cloud); the route's response
shape, the tenant-scoped graph snapshot it persists, and the current-estate
graph read are what is under test.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agent_bom.api.routes import cloud as cloud_routes
from agent_bom.api.server import app, configure_api
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_graph_store, set_graph_store, set_job_store
from agent_bom.cloud.side_scan_lifecycle import CleanupStatus, ExecutionStatus, SQLiteSideScanStateStore, new_side_scan_execution
from agent_bom.cloud.side_scan_targets import SIDE_SCAN_STATE_DB_ENV, CloudSideScanExecutionResult, side_scan_state_db_path
from agent_bom.core.cloud_identity import cloud_resource_node_id
from agent_bom.models import Package, Severity, Vulnerability
from tests._side_scan_test_auth import authorized_side_scan_orchestration as authorized_side_scan_orchestration

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
TENANT = "tenant-vm"
PROJECT = "demo-proj"
ZONE = "us-central1-a"
VM_ID = cloud_resource_node_id("gcp", "compute:instance", {"id": "1234567890123", "zone": ZONE, "project_id": PROJECT}, PROJECT, "")


def _headers(tenant: str = TENANT) -> dict[str, str]:
    return {"X-Agent-Bom-Role": "admin", "X-Agent-Bom-Tenant-ID": tenant, "X-Agent-Bom-Proxy-Secret": PROXY_SECRET}


def setup_module() -> None:
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    configure_api(api_key=None)


def teardown_module() -> None:
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)
    set_job_store(InMemoryJobStore())


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api.graph_store import SQLiteGraphStore

    monkeypatch.setenv(SIDE_SCAN_STATE_DB_ENV, str(tmp_path / "side_scan_state.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_ROLLUP_PREWARM", "0")
    monkeypatch.setenv("AGENT_BOM_FINDING_REACHABILITY_PREWARM", "0")
    original = _get_graph_store()
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    set_job_store(InMemoryJobStore())
    try:
        yield
    finally:
        set_graph_store(original)


def _executor(**kwargs) -> list[CloudSideScanExecutionResult]:
    store = SQLiteSideScanStateStore(side_scan_state_db_path())
    record = store.create_or_get(
        new_side_scan_execution(
            tenant_id=kwargs["tenant_id"],
            provider=kwargs["provider"],
            account_id=kwargs["account_id"],
            target_id=kwargs["target_id"],
            collector_id=kwargs["collector_id"],
            idempotency_key=kwargs["idempotency_key"],
        )
    )
    running = record.transition(status=ExecutionStatus.RUNNING, phase="scanning")
    store.save(running, expected_version=record.state_version)
    complete = running.transition(
        status=ExecutionStatus.SCAN_COMPLETE,
        phase="finished",
        cleanup_status=CleanupStatus.COMPLETE,
        package_count=1,
        vulnerability_count=1,
    )
    store.save(complete, expected_version=running.state_version)
    vuln = Vulnerability(id="CVE-2099-0001", summary="synthetic", severity=Severity.CRITICAL, fixed_version="3.0.3")
    return [
        CloudSideScanExecutionResult(
            provider=kwargs["provider"],
            target_type="persistent_disk",
            target_id=kwargs["target_id"],
            account_id=kwargs["account_id"],
            location=kwargs["location"],
            execution_id=record.execution_id,
            instance_id="1234567890123",
            instance_name="api-1",
            packages=[Package(name="openssl", version="3.0.2", ecosystem="deb", vulnerabilities=[vuln])],
            vulnerability_count=1,
            cleaned_up=True,
        )
    ]


def _body() -> dict:
    return {
        "connection_id": "fixture-connection",
        "provider": "gcp",
        "target_id": f"projects/{PROJECT}/zones/{ZONE}/disks/os",
        "account_id": PROJECT,
        "location": ZONE,
        "collector_id": "collector-vm",
    }


def test_side_scan_response_carries_packages_and_cves_per_vm(monkeypatch) -> None:
    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _executor)

    body = TestClient(app).post("/v1/cloud/side-scan", headers=_headers(), json=_body()).json()

    result = body["result"]
    assert result["instance_id"] == "1234567890123"
    assert result["packages"][0]["vulnerabilities"][0]["id"] == "CVE-2099-0001"
    assert result["packages_truncated"] is False
    assert result["package_count"] == 1
    assert body["graph"]["status"] == "persisted"
    assert body["graph"]["scan_id"]


def test_side_scan_vm_cves_are_in_the_tenant_graph_and_attack_paths(monkeypatch) -> None:
    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _executor)
    client = TestClient(app)
    scan_id = client.post("/v1/cloud/side-scan", headers=_headers(), json=_body()).json()["graph"]["scan_id"]

    pinned = client.get(f"/v1/graph?scan_id={scan_id}&limit=500", headers=_headers()).json()
    estate = client.get("/v1/graph?limit=500", headers=_headers()).json()
    paths = client.get(f"/v1/graph/attack-paths?scan_id={scan_id}", headers=_headers()).json()
    other_tenant = client.get(f"/v1/graph?scan_id={scan_id}", headers=_headers("tenant-other"))

    for graph in (pinned, estate):
        ids = {node["id"] for node in graph["nodes"]}
        assert VM_ID in ids and "vuln:CVE-2099-0001" in ids
    rows = paths.get("attack_paths") or paths.get("paths") or paths.get("items") or []
    assert any(row["hops"][0] == VM_ID and row["hops"][-1] == "vuln:CVE-2099-0001" for row in rows), paths
    assert other_tenant.status_code == 404 or VM_ID not in {n["id"] for n in other_tenant.json().get("nodes", [])}
