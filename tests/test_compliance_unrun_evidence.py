"""A control is only passed or failed on evidence that actually ran.

Three ways the scorecard asserted a control status no check produced:

1. The NIST 800-53 catalog line filtered vulnerability-intrinsic tags per
   CONTROL, so SR-3 (stamped on every CVE) and SI-4 (stamped on high severity)
   leaked through because CIS checks also evidence those controls — a HIGH CVE
   with no CWE failed SI-4/SR-3 on evidencing checks that never ran.
2. RA-5 (and every other scan-is-the-evidence control) read
   ``pass fresh_scan_evidence`` even when the vulnerability lane of that scan
   was partial.
3. CMMC RA.L2-3.11.2 — the 800-171 counterpart of RA-5 — failed on every CVE,
   and FedRAMP RA-5 read not_evaluated while NIST RA-5 passed on the same scan.
"""

from __future__ import annotations

from datetime import datetime, timezone

from starlette.testclient import TestClient

from agent_bom.api.server import JobStatus, _get_store, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.compliance_nist_catalog import build_nist_800_53_catalog_line
from agent_bom.evidence.control_modes import DETECTIVE_CONTROLS, detective_control_status
from agent_bom.models import Agent, AgentType, BlastRadius, Package, Severity, Vulnerability
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _tagged_row(*, severity: Severity = Severity.HIGH, cwe_ids: list[str] | None = None, vuln_id: str = "CVE-2026-1000") -> dict:
    """A serialized row carrying the tags every production tagger emits."""
    from agent_bom.scanners.package_scan import apply_framework_tags

    br = BlastRadius(
        vulnerability=Vulnerability(id=vuln_id, summary="t", severity=severity, cwe_ids=list(cwe_ids or [])),
        package=Package(name="demo", version="1.0.0", ecosystem="pypi"),
        affected_servers=[],
        affected_agents=[Agent(name="agent-a", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp/a.py")],
        exposed_credentials=[],
        exposed_tools=[],
    )
    apply_framework_tags(br)
    from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS

    return {
        "vulnerability_id": vuln_id,
        "severity": severity.value,
        "package": "demo@1.0.0",
        "affected_agents": ["agent-a"],
        "cwe_ids": list(cwe_ids or []),
        **{field: list(getattr(br, field, []) or []) for field in COMPLIANCE_TAG_FIELDS},
    }


# ── 1. NIST catalog: filter per evidencing check, not per control ─────────────


def test_high_cve_without_cwe_evaluates_no_catalog_control() -> None:
    row = _tagged_row(severity=Severity.HIGH)
    assert {"SI-4", "SR-3"} <= set(row["nist_800_53_tags"]), "precondition: the tagger stamps SI-4/SR-3"

    line = build_nist_800_53_catalog_line([row], {}, scan_count=1)

    by_id = {c["control_id"]: c["status"] for c in line["controls"]}
    assert "SI-4" not in by_id, "SI-4 failed on CIS alarm checks that never ran"
    assert "SR-3" not in by_id, "SR-3 failed on an evidencing check that never ran"
    assert line["summary"]["evaluated"] == 0
    assert line["status"] == "no_data"


def test_cwe_check_still_evidences_its_own_control_only() -> None:
    row = _tagged_row(severity=Severity.HIGH, cwe_ids=["CWE-20"])

    line = build_nist_800_53_catalog_line([row], {}, scan_count=1)

    by_id = {c["control_id"]: c["status"] for c in line["controls"]}
    assert by_id.get("SI-10") == "fail", "the CWE-20 check ran and evidences SI-10"
    assert "SI-4" not in by_id
    assert "SR-3" not in by_id


def test_cis_check_that_ran_still_evaluates_si4_alongside_an_unrelated_cve() -> None:
    row = _tagged_row(severity=Severity.HIGH)

    line = build_nist_800_53_catalog_line([row], {("aws", "4.1"): "pass"}, scan_count=1)

    by_id = {c["control_id"]: c for c in line["controls"]}
    assert by_id["SI-4"]["status"] == "pass", "only the CIS alarm check ran for SI-4"
    assert by_id["SI-4"]["findings"] == 0


def test_credential_exposure_evidences_its_cwe_798_controls() -> None:
    """Credential findings are tagged through the CWE-798 table row even when
    the row carries no explicit CWE — that check did run."""
    from agent_bom.finding import FindingSource, FindingType
    from agent_bom.framework_mapping import controls_for_finding_shape

    tags = controls_for_finding_shape(FindingType.CREDENTIAL_EXPOSURE, source=FindingSource.MCP_SCAN)
    row = {
        "vulnerability_id": "cred-1",
        "severity": "high",
        "finding_type": "CREDENTIAL_EXPOSURE",
        "nist_800_53_tags": tags["nist_800_53_tags"],
    }

    line = build_nist_800_53_catalog_line([row], {}, scan_count=1)

    assert line["summary"]["evaluated"] > 0
    assert all(c["status"] == "fail" for c in line["controls"])


# ── 2. Detective controls need complete vulnerability coverage ────────────────


def test_detective_status_withholds_pass_on_incomplete_vulnerability_coverage() -> None:
    now = datetime.now(timezone.utc)
    assert detective_control_status(scan_count=1, latest_scan=now.isoformat(), now=now, vulnerability_coverage_incomplete=True) == (
        "not_assessed",
        "vulnerability_coverage_incomplete",
    )


def _put_job(blast: list[dict], *, scan_run: dict | None = None, job_id: str = "job-unrun") -> None:
    from agent_bom.api.server import ScanJob, ScanRequest

    now = datetime.now(timezone.utc).isoformat()
    job = ScanJob(job_id=job_id, tenant_id="default", created_at=now, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = now
    job.result = {"agents": [], "blast_radius": blast, "threat_framework_summary": {}}
    if scan_run is not None:
        job.result["scan_run"] = scan_run
    _get_store().put(job)


_PARTIAL_VULN_RUN = {
    "outcome": "partial",
    "issues": [
        {
            "code": "vulnerability_coverage_gap",
            "stage": "scanning",
            "source": "vulnerability-data",
            "message": "osv: advisory source unavailable",
            "severity": "warning",
            "affects_coverage": True,
        }
    ],
}


def _detective_statuses(payload: dict) -> dict[str, tuple[str, str]]:
    def pick(key: str, control: str) -> tuple[str, str]:
        row = next(c for c in payload[key] if c["control_id"] == control)
        return row["status"], row["evidence_reason"]

    return {
        "nist RA-5": pick("nist_800_53", "RA-5"),
        "fedramp RA-5": pick("fedramp", "RA-5"),
        "cmmc RA.L2-3.11.2": pick("cmmc", "RA.L2-3.11.2"),
    }


def test_partial_vulnerability_scan_never_passes_ra5() -> None:
    set_job_store(InMemoryJobStore())
    _put_job([_tagged_row()], scan_run=_PARTIAL_VULN_RUN)
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    ra5 = next(c for c in payload["nist_800_53"] if c["control_id"] == "RA-5")
    assert ra5["status"] == "not_assessed"
    assert ra5["evidence_reason"] == "vulnerability_coverage_incomplete"
    cm8 = next(c for c in payload["nist_800_53"] if c["control_id"] == "CM-8")
    assert cm8["status"] == "pass", "discovery still produced the component inventory"


def test_non_vulnerability_lane_gap_keeps_ra5_passing() -> None:
    set_job_store(InMemoryJobStore())
    run = {
        "outcome": "partial",
        "issues": [
            {
                "code": "collector_unavailable",
                "stage": "discovery",
                "source": "k8s",
                "message": "cluster unreachable",
                "severity": "warning",
                "affects_coverage": True,
            }
        ],
    }
    _put_job([_tagged_row()], scan_run=run)
    with TestClient(app) as client:
        payload = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    ra5 = next(c for c in payload["nist_800_53"] if c["control_id"] == "RA-5")
    assert ra5["status"] == "pass"


# ── 3. CMMC / FedRAMP scan-is-the-evidence controls match NIST RA-5 ───────────


def test_cmmc_tagger_never_fails_the_scanning_practice() -> None:
    row = _tagged_row()
    assert "RA.L2-3.11.2" not in row["cmmc_tags"]
    assert "CM.L2-3.4.3" not in row["cmmc_tags"], "a CVE is not evidence about change control"
    assert "SI.L2-3.14.1" in row["cmmc_tags"], "flaw remediation is still failed by the CVE"


def test_cmmc_and_fedramp_declare_their_detective_controls() -> None:
    assert "RA.L2-3.11.2" in DETECTIVE_CONTROLS["cmmc_tags"]
    assert {"RA-5", "CM-8"} <= DETECTIVE_CONTROLS["fedramp_tags"]


def test_same_scan_ra5_agrees_across_nist_fedramp_and_cmmc() -> None:
    set_job_store(InMemoryJobStore())
    _put_job([_tagged_row(), _tagged_row(severity=Severity.CRITICAL, vuln_id="CVE-2026-1001")])
    with TestClient(app) as client:
        complete = _detective_statuses(client.get("/v1/compliance", headers=_AUTH_HEADERS).json())

    assert set(complete.values()) == {("pass", "fresh_scan_evidence")}, complete

    set_job_store(InMemoryJobStore())
    _put_job([_tagged_row()], scan_run=_PARTIAL_VULN_RUN)
    with TestClient(app) as client:
        partial = _detective_statuses(client.get("/v1/compliance", headers=_AUTH_HEADERS).json())

    assert set(partial.values()) == {("not_assessed", "vulnerability_coverage_incomplete")}, partial

    set_job_store(InMemoryJobStore())
    with TestClient(app) as client:
        empty = _detective_statuses(client.get("/v1/compliance", headers=_AUTH_HEADERS).json())

    assert set(empty.values()) == {("not_assessed", "no_completed_scan")}, empty


# ── CLI narrative from a saved report agrees with the API ─────────────────────


def _saved_report(*, scan_run: dict | None = None, findings: list[dict] | None = None) -> dict:
    data: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"total_agents": 1, "total_packages": 1, "total_vulnerabilities": 1},
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2026-2000",
                "severity": "high",
                "package": "flask@1.0.0",
                "ecosystem": "pypi",
                "affected_agents": ["claude"],
                "owasp_tags": ["LLM05"],
                "nist_800_53_tags": ["SI-10"],
            }
        ],
    }
    if scan_run is not None:
        data["scan_run"] = scan_run
    if findings is not None:
        data["findings"] = findings
    return data


def test_cli_narrative_withholds_scanning_practice_on_partial_saved_scan() -> None:
    from agent_bom.cli._history import _report_from_json
    from agent_bom.output.compliance_narrative import generate_compliance_narrative

    complete = generate_compliance_narrative(_report_from_json(_saved_report()), framework="cmmc")
    partial = generate_compliance_narrative(_report_from_json(_saved_report(scan_run=_PARTIAL_VULN_RUN)), framework="cmmc")

    assert complete.framework_narratives[0].status == "evidence_current"
    assert partial.framework_narratives[0].status == "not_evaluated"


def test_cli_reload_recovers_cwe_evidence_from_the_finding_stream() -> None:
    """Older saved reports carry CWEs only on the unified findings; the NIST
    catalog check must still see the CWE that evidences SI-10."""
    from agent_bom.cli._history import _report_from_json
    from agent_bom.output.compliance_narrative import generate_compliance_narrative

    finding = {
        "finding_type": "CVE",
        "cve_id": "CVE-2026-2000",
        "cwe_ids": ["CWE-20"],
        "evidence": {"package_name": "flask", "package_version": "1.0.0"},
    }
    without = generate_compliance_narrative(_report_from_json(_saved_report()), framework="nist-800-53")
    joined = generate_compliance_narrative(_report_from_json(_saved_report(findings=[finding])), framework="nist-800-53")

    assert without.nist_800_53_catalog["status"] == "no_data"
    assert {c["control_id"]: c["status"] for c in joined.nist_800_53_catalog["controls"]} == {"SI-10": "fail"}
