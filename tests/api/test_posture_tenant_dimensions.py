"""``/v1/posture`` dimensions are tenant-wide, on the overview's own basis.

The headline grade and the overview tiles read the tenant's current open
findings across every current scan. The per-dimension breakdown must read the
same set: a newer cloud scan with no MCP servers must not report credential
hygiene as 100 while an older, still-current agent scan exposes credentials
that the overview counts.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from agent_bom.cli import main
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "posture-tenant-dimensions"
AGENT_SCAN = "posture-tenant-agent-scan"
CLOUD_SCAN = "posture-tenant-cloud-scan"


@pytest.fixture(scope="module")
def demo_report(tmp_path_factory: pytest.TempPathFactory) -> dict:
    out = Path(tmp_path_factory.mktemp("posture-dims")) / "report.json"
    result = CliRunner().invoke(main, ["scan", "--offline", "--demo", "-f", "json", "-q", "-o", str(out)])
    assert out.is_file(), result.output
    return json.loads(out.read_text())


@pytest.fixture(autouse=True)
def _auth_env():
    enable_trusted_proxy_env()
    yield
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())


def _stamp(offset_minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _job(job_id: str, result: dict, *, request: ScanRequest, minutes_ago: int) -> ScanJob:
    stamp = _stamp(minutes_ago)
    job = ScanJob(job_id=job_id, tenant_id=TENANT, created_at=stamp, request=request)
    job.status = JobStatus.DONE
    job.completed_at = stamp
    job.result = {**result, "scan_id": job_id}
    return job


def _cloud_result() -> dict:
    """A newer scan of a different target: one critical CVE, no MCP servers."""
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="openssl", asset_type="package", identifier="pkg:deb/debian/openssl@3.0.0?image=edge"),
        severity="critical",
        cve_id="CVE-2026-7777",
    ).to_dict()
    return {
        "summary": {"total_packages": 1, "total_findings": 1, "total_vulnerabilities": 1},
        "has_mcp_context": False,
        "agents": [],
        "findings": [finding],
        # The single-scan scorecard this scan carries: no servers, so a clean
        # credential dimension. On its own it is right; tenant-wide it is not.
        "posture_scorecard": {
            "grade": "D",
            "score": 61.0,
            "summary": "Scan-time scorecard",
            "dimensions": {
                "credential_hygiene": {
                    "name": "Credential Hygiene",
                    "score": 100.0,
                    "weight": 0.2,
                    "weighted_score": 20.0,
                    "details": "No credential exposure detected",
                    "assessed": True,
                },
            },
        },
    }


def _seed(*jobs: ScanJob) -> TestClient:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.routes import compliance, overview

    set_job_store(InMemoryJobStore())
    get_compliance_hub_store().clear(TENANT)
    compliance._POSTURE_COUNTS_CACHE.clear()
    overview._reset_overview_cache()
    for job in jobs:
        _get_store().put(job)
    return TestClient(app)


def _read(client: TestClient) -> tuple[dict, dict]:
    headers = proxy_headers(role="analyst", tenant=TENANT)
    posture = client.get("/v1/posture", headers=headers)
    overview = client.get("/v1/overview", headers=headers)
    assert posture.status_code == overview.status_code == 200, (posture.text, overview.text)
    return posture.json(), overview.json()


def test_single_scan_dimensions_equal_that_scans_scorecard(demo_report: dict) -> None:
    """On one scan the tenant-wide basis is that scan: same scores, same semantics."""
    report = copy.deepcopy(demo_report)
    client = _seed(_job(AGENT_SCAN, report, request=ScanRequest(), minutes_ago=5))

    posture, _overview = _read(client)

    expected = report["posture_scorecard"]["dimensions"]
    got = posture["dimensions"]
    assert set(got) == set(expected)
    for key, dimension in expected.items():
        assert got[key]["score"] == dimension["score"], (key, got[key], dimension)
        assert got[key]["weight"] == dimension["weight"], key
        assert got[key]["details"] == dimension["details"], key
        assert got[key]["assessed"] == dimension["assessed"], key


def test_dimensions_reflect_the_union_of_current_open_findings(demo_report: dict) -> None:
    agent_scan = _job(AGENT_SCAN, copy.deepcopy(demo_report), request=ScanRequest(), minutes_ago=30)
    cloud_scan = _job(CLOUD_SCAN, _cloud_result(), request=ScanRequest(images=["registry.example/edge:1"]), minutes_ago=1)
    client = _seed(agent_scan, cloud_scan)

    posture, overview = _read(client)
    dimensions = posture["dimensions"]
    basis = posture["dimensions_basis"]

    assert basis["basis"] == "tenant_current_findings"
    assert sorted(basis["scan_ids"]) == sorted([AGENT_SCAN, CLOUD_SCAN])

    # Credential hygiene is not the newer scan's clean 100: the older,
    # still-current agent scan exposes credentials, and the overview says so.
    assert overview["headline"]["credential_exposed"] > 0
    assert basis["credential_exposed_findings"] == overview["headline"]["credential_exposed"]
    credentials = dimensions["credential_hygiene"]
    assert credentials["score"] < 100.0
    assert credentials["details"] == demo_report["posture_scorecard"]["dimensions"]["credential_hygiene"]["details"]

    # Vulnerability posture counts both scans' open CVEs: the demo's plus the
    # cloud scan's critical.
    demo_vulns = demo_report["posture_scorecard"]["dimensions"]["vulnerability_posture"]["details"]
    demo_total = int(demo_vulns.split(" ", 1)[0])
    assert dimensions["vulnerability_posture"]["details"].startswith(f"{demo_total + 1} vulnerability occurrences (3 critical")
    assert basis["vulnerability_findings"] == demo_total + 1

    # Open-finding basis agrees with the overview's occurrence histogram.
    assert basis["open_findings"] == overview["finding_counts"]["total"]


def test_skipped_vulnerability_lane_stays_not_assessed(demo_report: dict) -> None:
    from agent_bom.evidence.scan_run import VULNERABILITY_SCAN_SKIPPED_CODE

    report = copy.deepcopy(demo_report)
    report["findings"] = [row for row in report["findings"] if row.get("finding_type") != "CVE"]
    report["blast_radius"] = []
    report["scan_run"] = {**report["scan_run"], "issues": [{"code": VULNERABILITY_SCAN_SKIPPED_CODE, "stage": "scanning"}]}
    client = _seed(_job(AGENT_SCAN, report, request=ScanRequest(), minutes_ago=5))

    posture, _overview = _read(client)

    for key in ("vulnerability_posture", "active_exploitation"):
        assert posture["dimensions"][key]["assessed"] is False, key
        assert posture["dimensions"][key]["weighted_score"] == 0.0, key


def test_open_credential_exposure_counts_agree_with_the_overview() -> None:
    """A finding-only credential counts once in the dimension; a suppressed one nowhere."""
    result = _cloud_result()
    exposing = dict(result["findings"][0])
    exposing.update(exposed_credentials=["EDGE_DEPLOY_TOKEN"], affected_servers=["edge-runner"])
    suppressed = dict(exposing)
    suppressed.update(
        id="suppressed-exposure",
        finding_id="suppressed-exposure",
        cve_id="CVE-2026-8888",
        vulnerability_id="CVE-2026-8888",
        exposed_credentials=["EDGE_ADMIN_TOKEN"],
        # Operator VEX: kept as evidence, not an open finding.
        suppressed=True,
        suppression_state="vex",
        vex_suppressed=True,
        vex_source="operator",
        vex_status="not_affected",
    )
    result["findings"] = [exposing, suppressed]
    client = _seed(_job(CLOUD_SCAN, result, request=ScanRequest(images=["registry.example/edge:1"]), minutes_ago=1))

    posture, overview = _read(client)

    assert overview["headline"]["credential_exposed"] == 1
    assert posture["dimensions_basis"]["credential_exposed_findings"] == 1
    assert posture["dimensions"]["credential_hygiene"]["details"] == "1 unique credentials across 1 servers"
