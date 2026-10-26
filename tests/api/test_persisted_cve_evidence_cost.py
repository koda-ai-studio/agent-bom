"""One-advisory lookups sanitize only the rows for that advisory, not the tenant's whole finding set."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_bom import finding_scope
from agent_bom.api.scan_finding_read import persisted_finding_evidence
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from tests.api.test_findings_owner_sla import _completed_job
from tests.api.test_scan_job_sla_history import scan_store  # noqa: F401 - fixture

TENANT = "history-tenant"


def _finding(index: int) -> Finding:
    cve = f"CVE-2026-{1000 + index}"
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name=f"lib{index}", asset_type="package", identifier=f"pkg:pypi/lib{index}@1.0.0"),
        severity="high",
        cve_id=cve,
        title=f"{cve}: lib{index}@1.0.0",
        evidence={"package_name": f"lib{index}", "package_version": "1.0.0"},
    )


@pytest.fixture
def sanitized(scan_store, monkeypatch):  # noqa: F811 - fixture
    row = _completed_job(TENANT, [_finding(index) for index in range(40)], generated_at=datetime(2026, 8, 1, tzinfo=timezone.utc))
    row.job_id = f"{TENANT}-repo-a-8"
    row.target = {"path": "repo-a"}
    scan_store.put(row)
    calls: list[str] = []
    original = finding_scope.safe_finding_response_payload

    def counted(payload, *args, **kwargs):
        calls.append(str(payload.get("cve_id") or ""))
        return original(payload, *args, **kwargs)

    monkeypatch.setattr(finding_scope, "safe_finding_response_payload", counted)
    return calls


def test_unknown_advisory_sanitizes_nothing(sanitized):
    evidence = persisted_finding_evidence(tenant_id=TENANT, cve_id="CVE-2099-0001")

    assert evidence["available"] is True
    assert evidence["findings"] == []
    assert sanitized == []


def test_known_advisory_sanitizes_only_its_rows(sanitized):
    evidence = persisted_finding_evidence(tenant_id=TENANT, cve_id="cve-2026-1007")

    assert [row["cve_id"] for row in evidence["findings"]] == ["CVE-2026-1007"]
    assert set(sanitized) == {"CVE-2026-1007"}
