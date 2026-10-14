"""A detective control passes only on a scan whose lane actually produced evidence.

"Monitor and scan for vulnerabilities" (RA-5, CIS-07.x, CC7.1, ID.RA-01) is
evidenced by a vulnerability lane that evaluated packages; "maintain a component
inventory" (CM-8, CIS-02.1) by an inventory that listed components. A completed
IaC-only, browser-only or ``--no-scan`` run evidences neither, and used to pass
every detective control with ``fresh_scan_evidence``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from starlette.testclient import TestClient

from agent_bom.api.server import JobStatus, _get_store, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.evidence.control_modes import LANE_INVENTORY, LANE_VULNERABILITY, detective_lane
from agent_bom.evidence.detective_evidence import DetectiveScanEvidence, detective_lanes_evidenced, result_detective_lanes
from agent_bom.evidence.scan_run import (
    VULNERABILITY_SCAN_SKIPPED_CODE,
    VULNERABILITY_SCAN_SKIPPED_MESSAGE,
    ScanRun,
    vulnerability_coverage_incomplete,
    vulnerability_scan_skipped_issue,
)
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")
_SKIPPED_RUN = {"outcome": "complete", "issues": [vulnerability_scan_skipped_issue().to_dict()]}
_LEGACY_API_SKIPPED_RUN = {
    "outcome": "complete",
    "issues": [
        {
            "code": "scan_warning",
            "stage": "discovery",
            "source": "api",
            "message": VULNERABILITY_SCAN_SKIPPED_MESSAGE,
            "severity": "warning",
            "affects_coverage": False,
        }
    ],
}
_SCANNED_PERF = {"osv": {"packages_seen": 3}}
_CVE_ROW = {"vulnerability_id": "CVE-2026-3000", "severity": "high", "package": "flask@1.0.0", "nist_800_53_tags": ["SI-2"]}
_CIS_FAIL_ROW = {"vulnerability_id": "CKV_AWS_1", "severity": "high", "finding_type": "CIS_FAIL", "nist_800_53_tags": ["CM-6"]}


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _result(*, packages: int = 0, blast: list[dict] | None = None, scan_run: dict | None = None, perf: dict | None = None) -> dict:
    result: dict = {"agents": [], "summary": {"total_packages": packages}, "blast_radius": list(blast or [])}
    if scan_run is not None:
        result["scan_run"] = scan_run
    if perf is not None:
        result["scan_performance"] = perf
    return result


# ── lane derivation ───────────────────────────────────────────────────────────


def test_skip_receipt_is_not_a_coverage_gap() -> None:
    issue = vulnerability_scan_skipped_issue()
    assert issue.code == VULNERABILITY_SCAN_SKIPPED_CODE
    assert issue.affects_coverage is False
    assert ScanRun(issues=[issue]).outcome.value == "complete"
    assert vulnerability_coverage_incomplete(SimpleNamespace(scan_run=ScanRun(issues=[issue]), coverage_warnings=[])) is False


def test_detective_lane_split() -> None:
    assert detective_lane("nist_800_53_tags", "CM-8") == LANE_INVENTORY
    assert detective_lane("cis_tags", "CIS-02.1") == LANE_INVENTORY
    for tag_field, control in [
        ("nist_800_53_tags", "RA-5"),
        ("cis_tags", "CIS-07.1"),
        ("cis_tags", "CIS-07.5"),
        ("soc2_tags", "CC7.1"),
        ("nist_csf_tags", "ID.RA-01"),
        ("cmmc_tags", "RA.L2-3.11.2"),
    ]:
        assert detective_lane(tag_field, control) == LANE_VULNERABILITY


def test_lanes_from_serialized_results() -> None:
    both = {LANE_VULNERABILITY, LANE_INVENTORY}
    # IaC-only / browser-only: nothing inventoried, nothing vulnerability-scanned.
    assert result_detective_lanes(_result(blast=[_CIS_FAIL_ROW])) == frozenset()
    # CLI scan: the OSV lane evaluated packages.
    assert result_detective_lanes(_result(packages=3, perf=_SCANNED_PERF)) == both
    # CLI scan whose lane saw no packages (perf block present, zero seen).
    assert result_detective_lanes(_result(packages=0, perf={"osv": {"packages_seen": 0}})) == frozenset()
    # API scan: no perf block; inventoried packages went through the scanner.
    assert result_detective_lanes(_result(packages=3)) == both
    assert result_detective_lanes(_result(blast=[_CVE_ROW])) == both
    # --no-scan (CLI receipt, and the message legacy API reports carry).
    assert result_detective_lanes(_result(packages=3, scan_run=_SKIPPED_RUN)) == {LANE_INVENTORY}
    assert result_detective_lanes(_result(packages=3, scan_run=_LEGACY_API_SKIPPED_RUN)) == {LANE_INVENTORY}
    assert result_detective_lanes("not-a-dict") == frozenset()


def test_lanes_from_report_objects() -> None:
    report = SimpleNamespace(scan_run=ScanRun(issues=[vulnerability_scan_skipped_issue()]), total_packages=4, blast_radii=[])
    assert detective_lanes_evidenced(report) == {LANE_INVENTORY}
    report = SimpleNamespace(scan_run=ScanRun(), total_packages=0, blast_radii=[], scan_performance_data=None)
    assert detective_lanes_evidenced(report) == frozenset()


def test_lane_scoring_uses_the_lane_evidence_timestamp() -> None:
    now = datetime.now(timezone.utc)
    stale = (now - timedelta(days=400)).isoformat()
    evidence = DetectiveScanEvidence(
        scan_count=2,
        latest_scan=now.isoformat(),
        lane_scans={LANE_INVENTORY: (2, now.isoformat()), LANE_VULNERABILITY: (1, stale)},
    )
    assert evidence.control_status("nist_800_53_tags", "CM-8") == ("pass", "fresh_scan_evidence")
    assert evidence.control_status("nist_800_53_tags", "RA-5") == ("fail", "stale_scan_evidence")
    none = DetectiveScanEvidence(scan_count=1, latest_scan=now.isoformat(), lane_scans={})
    assert none.control_status("cis_tags", "CIS-07.1") == ("not_assessed", "detective_evidence_not_collected")


# ── API ───────────────────────────────────────────────────────────────────────


def _put(result: dict, *, job_id: str, completed_at: str | None = None) -> None:
    from agent_bom.api.server import ScanJob, ScanRequest

    now = completed_at or datetime.now(timezone.utc).isoformat()
    job = ScanJob(job_id=job_id, tenant_id="default", created_at=now, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = now
    job.result = result
    _get_store().put(job)


def _detective(payload: dict) -> dict[str, tuple[str, str]]:
    picks = {
        "cis CIS-02.1": ("cis_controls", "CIS-02.1"),
        "cis CIS-07.1": ("cis_controls", "CIS-07.1"),
        "cis CIS-07.5": ("cis_controls", "CIS-07.5"),
        "soc2 CC7.1": ("soc2", "CC7.1"),
        "csf ID.RA-01": ("nist_csf", "ID.RA-01"),
        "nist RA-5": ("nist_800_53", "RA-5"),
        "nist CM-8": ("nist_800_53", "CM-8"),
        "fedramp RA-5": ("fedramp", "RA-5"),
    }
    out = {}
    for label, (key, control) in picks.items():
        row = next(c for c in payload[key] if c["control_id"] == control)
        out[label] = (row["status"], row["evidence_reason"])
    return out


def _compliance() -> dict:
    with TestClient(app) as client:
        response = client.get("/v1/compliance", headers=_AUTH_HEADERS)
    assert response.status_code == 200
    return response.json()


def test_iac_only_scan_passes_no_detective_control() -> None:
    set_job_store(InMemoryJobStore())
    _put(_result(blast=[_CIS_FAIL_ROW]), job_id="iac-only")
    statuses = _detective(_compliance())
    assert set(statuses.values()) == {("not_assessed", "detective_evidence_not_collected")}, statuses


def test_no_scan_run_evidences_inventory_but_not_vulnerability_scanning() -> None:
    set_job_store(InMemoryJobStore())
    _put(_result(packages=5, blast=[_CIS_FAIL_ROW], scan_run=_SKIPPED_RUN), job_id="no-scan")
    statuses = _detective(_compliance())
    assert statuses.pop("cis CIS-02.1") == ("pass", "fresh_scan_evidence")
    assert statuses.pop("nist CM-8") == ("pass", "fresh_scan_evidence")
    assert set(statuses.values()) == {("not_assessed", "detective_evidence_not_collected")}, statuses


def test_vulnerability_scan_still_passes_every_detective_control() -> None:
    set_job_store(InMemoryJobStore())
    _put(_result(packages=3, blast=[_CVE_ROW], perf=_SCANNED_PERF), job_id="scanned")
    statuses = _detective(_compliance())
    assert set(statuses.values()) == {("pass", "fresh_scan_evidence")}, statuses


def test_iac_rescan_of_the_same_target_supersedes_its_vulnerability_scan() -> None:
    set_job_store(InMemoryJobStore())
    old = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    _put(_result(packages=3, blast=[_CVE_ROW], perf=_SCANNED_PERF), job_id="old-vuln", completed_at=old)
    _put(_result(blast=[_CIS_FAIL_ROW]), job_id="fresh-iac")
    statuses = _detective(_compliance())
    assert statuses["nist RA-5"] == ("not_assessed", "detective_evidence_not_collected"), statuses


def test_a_later_iac_scan_never_refreshes_an_old_vulnerability_scan() -> None:
    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=400)).isoformat()
    evidence = DetectiveScanEvidence.for_results(
        [(_result(packages=3, blast=[_CVE_ROW], perf=_SCANNED_PERF), old), (_result(blast=[_CIS_FAIL_ROW]), now.isoformat())],
        latest_scan=now.isoformat(),
    )
    assert evidence.control_status("nist_800_53_tags", "RA-5") == ("fail", "stale_scan_evidence")
    assert evidence.control_status("cis_tags", "CIS-07.1") == ("fail", "stale_scan_evidence")


# ── CLI narrative ─────────────────────────────────────────────────────────────


_SECRET_FINDING = {
    "id": "secret-1",
    "finding_type": "CREDENTIAL_EXPOSURE",
    "severity": "high",
    "title": "Committed AWS key",
    "cwe_ids": ["CWE-798"],
    "soc2_tags": ["CC6.1"],
    "asset": {"name": "app/.env", "asset_type": "file"},
    "evidence": {"file": "app/.env"},
}


def _saved(*, packages: int, blast: list[dict] | None = None, findings: list[dict] | None = None, scan_run: dict | None = None) -> dict:
    saved: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"total_agents": 0, "total_packages": packages, "total_vulnerabilities": 0},
        "blast_radius": list(blast or []),
        "findings": list(findings or []),
    }
    if scan_run is not None:
        saved["scan_run"] = scan_run
    return saved


def test_cli_narrative_scores_detective_controls_by_lane() -> None:
    from agent_bom.cli._history import _report_from_json
    from agent_bom.output.compliance_narrative import generate_compliance_narrative

    def status(saved: dict, framework: str) -> str:
        return generate_compliance_narrative(_report_from_json(saved), framework=framework).framework_narratives[0].status

    secrets_only = _saved(packages=0, findings=[_SECRET_FINDING])
    assert status(secrets_only, "cmmc") == "not_evaluated"
    assert status(_saved(packages=2, findings=[_SECRET_FINDING], scan_run=_SKIPPED_RUN), "cmmc") == "not_evaluated"
    assert status(_saved(packages=2, blast=[_CVE_ROW]), "cmmc") == "evidence_current"


# ── producers record the skip receipt ─────────────────────────────────────────


def test_cli_no_scan_records_the_skip_receipt(tmp_path) -> None:
    import json
    from pathlib import Path

    from click.testing import CliRunner

    from agent_bom.cli import main

    out = tmp_path / "report.json"
    fixture = Path(__file__).parent / "fixtures" / "iac"
    args = ["scan", "--offline", "--no-scan", "--no-discover", "-p", str(fixture), "-f", "json", "-q", "--exit-zero", "-o", str(out)]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text())
    codes = [issue["code"] for issue in report["scan_run"]["issues"]]
    assert VULNERABILITY_SCAN_SKIPPED_CODE in codes
    assert report["scan_run"]["outcome"] == "complete"
    assert result_detective_lanes(report) == frozenset()


def test_api_no_scan_import_evidences_inventory_not_vulnerability_scanning(tmp_path, monkeypatch) -> None:
    """Supplied CVEs in an imported SBOM are inventory, not proof a scan ran."""
    import json

    from agent_bom.api.models import ScanJob, ScanRequest
    from agent_bom.api.pipeline import _run_scan_sync
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, Severity, Vulnerability
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx

    package = Package(
        name="a",
        version="1",
        ecosystem="npm",
        vulnerabilities=[Vulnerability(id="CVE-TEST", severity=Severity.HIGH, summary="supplied evidence")],
    )
    agent = Agent(name="a", agent_type=AgentType.CUSTOM, config_path="/tmp/a", mcp_servers=[MCPServer(name="s", packages=[package])])
    source = tmp_path / "bom.json"
    source.write_text(json.dumps(to_cyclonedx(AIBOMReport(agents=[agent], blast_radii=[]))))
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: InMemoryJobStore())
    job = ScanJob(
        job_id="import-lanes", created_at="2026-10-05T00:00:00Z", request=ScanRequest(sbom=str(source), no_scan=True, offline=True)
    )
    _run_scan_sync(job)
    assert job.status == JobStatus.DONE
    assert job.result["summary"]["total_findings"] == 1
    assert result_detective_lanes(job.result) == {LANE_INVENTORY}
