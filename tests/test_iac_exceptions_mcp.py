"""MCP scan tool: repository IaC findings are surfaced and the bound tenant's approved IaC exceptions apply."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_bom.api import stores
from agent_bom.api.exception_store import InMemoryExceptionStore, VulnException
from agent_bom.api.suppression_approval import activate_suppression

POD = """apiVersion: v1
kind: Pod
metadata:
  name: node-debugger
  namespace: ops
spec:
  containers:
    - name: app
      image: nginx:1.25@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      securityContext:
        privileged: true
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "pod.yaml").write_text(POD)
    return tmp_path


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch):
    exceptions = InMemoryExceptionStore()
    exc = VulnException(
        iac_rule_id="K8S-001",
        iac_resource={"kind": "Pod", "name": "node-debugger"},
        reason="node debugger needs host access",
        requested_by="alice",
        expires_at=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        tenant_id="tenant-a",
    )
    activate_suppression(exc, actor="bob")
    exceptions.put(exc, tenant_id="tenant-a")
    old = stores._get_exception_store()
    stores.set_exception_store(exceptions)
    yield exc
    stores.set_exception_store(old)


async def _iac(repo: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict | None, list[str]]:
    from agent_bom.mcp_server_scan import consume_repo_tree_iac, run_scan_pipeline

    async def _no_vulns(agents, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", _no_vulns)
    _agents, _b, warnings, _s = await run_scan_pipeline(safe_path=Path, config_path=str(repo), no_discover=True, offline=True)
    data = consume_repo_tree_iac()
    assert consume_repo_tree_iac() is None
    return data, warnings


@pytest.mark.asyncio
async def test_bound_tenant_exception_applies_and_evidence_is_kept(repo: Path, store, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    data, _ = await _iac(repo, monkeypatch)
    assert data is not None
    assert all(row["rule_id"] != "K8S-001" for row in data["findings"])
    [row] = data["suppressed"]
    assert row["suppression"]["source"] == "tenant"
    assert row["suppression"]["approved_by"] == "bob"
    assert row["suppression"]["exception_id"] == store.exception_id


@pytest.mark.asyncio
async def test_another_tenant_binding_does_not_inherit_the_exception(repo: Path, store, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-b")
    data, _ = await _iac(repo, monkeypatch)
    assert data is not None
    assert any(row["rule_id"] == "K8S-001" for row in data["findings"])
    assert data["suppressed"] == []


@pytest.mark.asyncio
async def test_unavailable_store_applies_no_exceptions_and_warns(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _broken():
        raise RuntimeError("store down")

    monkeypatch.setattr("agent_bom.mcp_tools.exceptions._exception_store", _broken)
    data, warnings = await _iac(repo, monkeypatch)
    assert data is not None
    assert any(row["rule_id"] == "K8S-001" for row in data["findings"])
    assert any("Tenant IaC exceptions unavailable" in w for w in warnings)


def test_scan_report_carries_the_repository_iac_block() -> None:
    from agent_bom.mcp_server_scan import _REPO_TREE_IAC
    from agent_bom.mcp_tools.scanning import _attach_pipeline_evidence
    from agent_bom.models import AIBOMReport
    from agent_bom.output.json_fmt import to_json

    block = {"total": 0, "findings": [], "suppressed": [{"rule_id": "K8S-001", "suppressed": True}], "exceptions": {"accepted": 1}}
    _REPO_TREE_IAC.set(block)
    report = AIBOMReport(agents=[], blast_radii=[])
    _attach_pipeline_evidence(report, [], [])
    assert report.iac_findings_data == block
    assert to_json(report)["iac_findings"]["suppressed"][0]["rule_id"] == "K8S-001"
