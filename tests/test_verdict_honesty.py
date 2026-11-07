"""A verdict states no more than its evidence: name guesses, empty scopes, unreachable targets, unknown packages."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync
from agent_bom.cli import main
from agent_bom.evidence.malicious_basis import DEPENDENCY_CONFUSION, KNOWN_MALICIOUS, NAME_SIMILARITY, UNSPECIFIED, malicious_basis
from agent_bom.finding import malicious_package_to_finding
from agent_bom.malicious import check_dependency_confusion, check_typosquat
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.posture import compute_posture_scorecard
from agent_bom.scanners.package_coverage import _flag_suspicious_packages

TYPOSQUAT_REASON = "Possible typosquat of 'requests'"
CONFUSION_REASON = "Dependency confusion risk: 'acme-internal' matches internal naming patterns"
ADVISORY_REASON = "Known malicious package (MAL-2024-0001)"
_STANDALONE_MALICIOUS = re.compile(r"(?<!SUSPECTED )\bMALICIOUS\b")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _patch_scan(monkeypatch: pytest.MonkeyPatch, *, reason: str | None = None) -> None:
    """Replace only the network scan; the real heuristics flag the package unless ``reason`` says otherwise."""

    async def fake_scan(pkgs, **_kwargs):
        for pkg in pkgs:
            if reason:
                pkg.is_malicious, pkg.malicious_reason = True, reason
        _flag_suspicious_packages(pkgs)
        return 0

    monkeypatch.setattr("agent_bom.scanners.scan_packages", fake_scan)
    monkeypatch.setattr("agent_bom.cli._check_published.unpublished_pin", lambda *_args: None)


# ── D1: evidence basis ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "reason,expected",
    [
        (TYPOSQUAT_REASON, NAME_SIMILARITY),
        ("Possible typosquat of 'requests'; no published version", NAME_SIMILARITY),
        (CONFUSION_REASON, DEPENDENCY_CONFUSION),
        (ADVISORY_REASON, KNOWN_MALICIOUS),
        ("go.sum hash mismatch: tampered module", KNOWN_MALICIOUS),
        ("Content-confirmed executable pickle payload", KNOWN_MALICIOUS),
        (None, UNSPECIFIED),
    ],
)
def test_basis_follows_the_evidence(reason, expected):
    assert malicious_basis(reason) == expected


def test_package_and_finding_expose_the_basis_only_when_flagged():
    assert Package(name="a", version="1", ecosystem="pypi").malicious_basis is None
    pkg = Package(name="reqeusts", version="1", ecosystem="pypi", is_malicious=True, malicious_reason=TYPOSQUAT_REASON)
    assert pkg.malicious_basis == NAME_SIMILARITY


def test_real_typosquat_reads_suspected_and_still_exits_one(monkeypatch):
    _patch_scan(monkeypatch)
    result = CliRunner().invoke(main, ["check", "reqeusts@1.0.0", "--ecosystem", "pypi", "--no-color"])
    output = _flat(result.output)
    assert result.exit_code == 1, result.output
    assert "SUSPECTED MALICIOUS" in output
    assert "Possible typosquat of 'requests'" in output
    assert "name similarity" in output
    assert "no advisory reports" in output
    assert "confirm" in output.lower()
    assert not _STANDALONE_MALICIOUS.search(output)


def test_exit_zero_does_not_clear_a_suspected_package(monkeypatch):
    _patch_scan(monkeypatch)
    result = CliRunner().invoke(main, ["check", "reqeusts@1.0.0", "--ecosystem", "pypi", "--exit-zero", "--no-color"])
    assert result.exit_code == 1, result.output


def test_quiet_line_says_suspected(monkeypatch):
    _patch_scan(monkeypatch)
    result = CliRunner().invoke(main, ["check", "reqeusts@1.0.0", "--ecosystem", "pypi", "-q"])
    assert result.exit_code == 1
    assert "SUSPECTED MALICIOUS" in result.output
    assert not _STANDALONE_MALICIOUS.search(result.output)


@pytest.mark.parametrize(
    "spec,reason,verdict,basis",
    [
        ("reqeusts@1.0.0", None, "suspected_malicious", NAME_SIMILARITY),
        ("acme-internal@1.0.0", CONFUSION_REASON, "suspected_malicious", DEPENDENCY_CONFUSION),
        ("evil@1.0.0", ADVISORY_REASON, "malicious", KNOWN_MALICIOUS),
    ],
)
def test_json_carries_verdict_and_basis(monkeypatch, spec, reason, verdict, basis):
    _patch_scan(monkeypatch, reason=reason)
    result = CliRunner().invoke(main, ["check", spec, "--ecosystem", "pypi", "-f", "json"])
    payload = json.loads(result.output)
    assert result.exit_code == 1
    assert payload["exit_code"] == 1
    assert payload["verdict"] == verdict
    assert payload["canonical_verdict"] == verdict
    assert payload["is_malicious"] is True
    assert payload["malicious_basis"] == basis
    assert ("SUSPECTED MALICIOUS" in payload["message"]) == (verdict == "suspected_malicious")


def test_clean_json_has_a_null_basis(monkeypatch):
    _patch_scan(monkeypatch)
    result = CliRunner().invoke(main, ["check", "requests@2.32.3", "--ecosystem", "pypi", "-f", "json"])
    payload = json.loads(result.output)
    assert payload["verdict"] == "clean"
    assert payload["malicious_basis"] is None


def test_known_malicious_reads_malicious(monkeypatch):
    _patch_scan(monkeypatch, reason=ADVISORY_REASON)
    result = CliRunner().invoke(main, ["check", "evil@1.0.0", "--ecosystem", "pypi", "--no-color"])
    output = _flat(result.output)
    assert result.exit_code == 1
    assert "MALICIOUS package evil@1.0.0" in output
    assert "SUSPECTED" not in output
    assert "Do not install" in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason,status,basis",
    [
        ("Possible typosquat of requests", "suspected_malicious", NAME_SIMILARITY),
        (ADVISORY_REASON, "malicious", KNOWN_MALICIOUS),
    ],
)
async def test_mcp_check_keeps_the_same_verdict(reason, status, basis):
    from unittest.mock import patch

    from agent_bom.mcp_tools.scanning import check_impl

    async def fake_scan(packages, **_kwargs):
        packages[0].is_malicious, packages[0].malicious_reason = True, reason

    with patch("agent_bom.scanners.scan_packages", side_effect=fake_scan):
        raw = await check_impl(
            package="reqeusts@1.0.0",
            ecosystem="pypi",
            offline=True,
            _validate_ecosystem=lambda eco: eco,
            _truncate_response=lambda response: response,
        )
    payload = json.loads(raw)
    assert payload["status"] == status
    assert payload["canonical_verdict"] == status
    assert payload["is_malicious"] is True
    assert payload["malicious_basis"] == basis
    assert ("SUSPECTED MALICIOUS" in payload["message"]) == (status == "suspected_malicious")


def test_unpublished_typosquat_through_mcp_lookup_says_suspected():
    from agent_bom.mcp_tools.check_lookup import unresolved_result

    pkg = Package(name="reqeusts", version="latest", ecosystem="pypi")
    captured: dict = {}

    def service_result(verdict, message):
        captured.update(verdict=verdict, message=message)
        return ""

    unresolved_result(pkg, "reqeusts", "pypi", "Possible typosquat of 'requests'; no published version", service_result)
    assert captured["verdict"] == "suspected_malicious"
    assert "SUSPECTED MALICIOUS" in captured["message"]
    assert pkg.is_malicious is True


def _suspected_finding():
    pkg = Package(name="reqeusts", version="1.0.0", ecosystem="pypi", is_malicious=True, malicious_reason=TYPOSQUAT_REASON)
    return malicious_package_to_finding(pkg, affected_agents=["a"], affected_servers=["s"])


def test_synthesized_finding_says_suspected_and_stays_blocking():
    finding = _suspected_finding()
    assert finding.title == "Suspected malicious package: reqeusts@1.0.0"
    assert finding.is_malicious is True
    assert finding.severity == "critical"
    assert finding.evidence["malicious_basis"] == NAME_SIMILARITY
    assert finding.to_dict()["malicious_basis"] == NAME_SIMILARITY


def test_known_finding_title_is_unchanged():
    pkg = Package(name="evil", version="1", ecosystem="pypi", is_malicious=True, malicious_reason=ADVISORY_REASON)
    finding = malicious_package_to_finding(pkg, affected_agents=[], affected_servers=[])
    assert finding.title == "Malicious package: evil@1"
    assert finding.evidence["malicious_basis"] == KNOWN_MALICIOUS


def test_remediation_for_a_suspected_package_asks_to_confirm():
    from agent_bom.finding import _remediation_guidance_for_vulnerability

    pkg = Package(name="reqeusts", version="1.0.0", ecosystem="pypi", is_malicious=True, malicious_reason=TYPOSQUAT_REASON)
    text = _remediation_guidance_for_vulnerability(SimpleNamespace(id="X", references=[]), pkg)
    assert text.startswith("Confirm reqeusts is the package you intended")
    assert "immediately" not in text


def test_console_remediation_separates_suspected(monkeypatch):
    from rich.console import Console

    import agent_bom.output.console_remediation as remediation

    capture = Console(record=True, width=200)
    monkeypatch.setattr(remediation, "_console", lambda: capture)
    remediation._print_malicious(
        [
            {
                "package": "reqeusts",
                "current": "1.0.0",
                "reason": TYPOSQUAT_REASON,
                "suspected": True,
                "command": None,
                "agents": [],
            },
            {"package": "evil", "current": "1", "reason": ADVISORY_REASON, "suspected": False, "command": None, "agents": []},
        ]
    )
    text = capture.export_text()
    assert "1 MALICIOUS package(s) — remove immediately" in text
    assert "1 SUSPECTED MALICIOUS package(s)" in text
    assert "Confirm reqeusts@1.0.0" in text
    assert "Remove evil@1" in text


def test_remediation_action_for_suspected_group():
    import agent_bom.output.console_remediation as remediation

    group = {
        "is_malicious": True,
        "malicious_reason": TYPOSQUAT_REASON,
        "package": "reqeusts",
        "ecosystem": "pypi",
        "fix": None,
    }
    action = remediation._remediation_action(group)
    assert action.startswith("Confirm reqeusts is the package you intended")
    assert group["suspected"] is True
    assert group["reason"] == TYPOSQUAT_REASON


def test_scan_alert_says_suspected():
    from agent_bom.alerts.scan_alerts import alerts_from_scan_result

    package = {"name": "reqeusts", "version": "1", "is_malicious": True, "malicious_reason": TYPOSQUAT_REASON}
    report = {"agents": [{"mcp_servers": [{"packages": [package]}]}]}
    alert = next(a for a in alerts_from_scan_result(report) if a["detector"] == "scan_malicious")
    assert alert["message"].startswith("Suspected malicious package detected")
    assert alert["details"]["basis"] == NAME_SIMILARITY


def _report_with(pkg: Package) -> AIBOMReport:
    server = MCPServer(name="srv", command="npx", args=[], packages=[pkg])
    return AIBOMReport(agents=[Agent(name="a", agent_type=AgentType.CUSTOM, config_path="/x", mcp_servers=[server])], blast_radii=[])


def test_exports_carry_the_basis():
    from agent_bom.output import to_json
    from agent_bom.output.csv_fmt import to_csv
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx
    from agent_bom.output.sarif import to_sarif
    from agent_bom.output.spdx_fmt import to_spdx

    report = _report_with(Package(name="reqeusts", version="1.0.0", ecosystem="pypi", is_malicious=True, malicious_reason=TYPOSQUAT_REASON))

    rendered = json.dumps(to_json(report))
    assert f'"malicious_basis": "{NAME_SIMILARITY}"' in rendered
    assert "Suspected malicious package: reqeusts@1.0.0" in rendered

    rows = list(csv.DictReader(io.StringIO(to_csv(report))))
    assert rows and rows[0]["malicious_basis"] == NAME_SIMILARITY

    results = to_sarif(report)["runs"][0]["results"]
    assert results and results[0]["properties"]["malicious_basis"] == NAME_SIMILARITY

    component = next(c for c in to_cyclonedx(report)["components"] if c["name"] == "reqeusts")
    assert {"name": "agent-bom:malicious-basis", "value": NAME_SIMILARITY} in component["properties"]

    assert f"basis={NAME_SIMILARITY}" in json.dumps(to_spdx(report))


def test_exports_omit_the_basis_for_unflagged_packages():
    from agent_bom.output import to_json

    report = _report_with(Package(name="requests", version="2.32.3", ecosystem="pypi"))
    assert "malicious_basis" not in json.dumps(to_json(report))


@pytest.mark.parametrize("name", ["ctransformers", "parsing"])
def test_established_pypi_projects_are_not_guessed(name):
    # Checked on pypi.org 2026-11-06: ctransformers (marella, 30 releases since 2023),
    # parsing (Jason Evans, 10 releases since 2012). OSV lists no malware for either.
    assert check_typosquat(name, "pypi") is None


@pytest.mark.parametrize(
    "name,target",
    [("transformerss", "transformers"), ("pyparsng", "pyparsing"), ("reqeusts", "requests"), ("urlib3", "urllib3")],
)
def test_real_typosquats_are_still_caught(name, target):
    assert check_typosquat(name, "pypi") == target


def test_dependency_confusion_still_flags_and_reads_suspected(monkeypatch):
    pkg = Package(name="acme-internal", version="1.0.0", ecosystem="pypi")
    assert check_dependency_confusion(pkg)
    _flag_suspicious_packages([pkg])
    assert pkg.is_malicious is True
    assert pkg.malicious_basis == DEPENDENCY_CONFUSION


def test_scan_gate_says_suspected_and_exits_one(monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text("reqeusts==1.0.0\n")

    async def no_lookup(*_a, **_k):
        return {}

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", no_lookup)
    result = CliRunner().invoke(main, ["fs", str(tmp_path), "-f", "console"])
    assert result.exit_code == 1, result.output
    assert "suspected malicious package reqeusts" in _flat(result.output)


# ── D6: nothing evaluated ────────────────────────────────────────────────────


def _empty_fs_report(tmp_path: Path, *args: str) -> tuple[int, str, str]:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    target = tmp_path / "empty"
    target.mkdir(exist_ok=True)
    artifact = out / f"r.{args[1]}"
    result = CliRunner().invoke(main, ["fs", str(target), *args, "-o", str(artifact)])
    return result.exit_code, result.output, artifact.read_text()


def test_empty_directory_has_no_grade_and_says_nothing_was_found(tmp_path):
    exit_code, output, raw = _empty_fs_report(tmp_path, "-f", "json")
    report = json.loads(raw)
    assert exit_code == 0, output
    assert report["posture_grade"] == "N/A"
    assert report["posture_scorecard"]["no_data"] is True
    assert report["scan_run"]["outcome"] == "partial"
    issue = next(i for i in report["scan_run"]["issues"] if i["code"] == "nothing_to_scan")
    assert "Nothing to scan" in issue["message"]
    assert "empty" in issue["message"]
    assert issue["affects_coverage"] is True
    assert "Nothing to scan" in _flat(output)


def test_directory_with_clean_iac_is_a_complete_scan_with_a_passing_exit(tmp_path):
    target = tmp_path / "infra"
    target.mkdir()
    (target / "ok.tf").write_text('resource "null_resource" "ok" {}\n')
    artifact = tmp_path / "r.json"
    result = CliRunner().invoke(main, ["fs", str(target), "-f", "json", "-o", str(artifact)])
    report = json.loads(artifact.read_text())
    assert result.exit_code == 0, result.output
    assert not [i for i in report["scan_run"]["issues"] if i["code"] == "nothing_to_scan"]


def test_a_missing_path_still_fails(tmp_path):
    result = CliRunner().invoke(main, ["fs", str(tmp_path / "missing")])
    assert result.exit_code != 0, result.output


def test_fs_detects_iac_in_its_target_rather_than_the_working_directory(tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "Dockerfile").write_text("FROM scratch\n")
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.chdir(elsewhere)
    artifact = tmp_path / "r.json"
    result = CliRunner().invoke(main, ["fs", str(target), "-f", "json", "-o", str(artifact)])
    assert result.exit_code == 0, result.output
    assert "Auto-detected" not in result.output
    assert any(i["code"] == "nothing_to_scan" for i in json.loads(artifact.read_text())["scan_run"]["issues"])


def test_empty_directory_sarif_reports_na(tmp_path):
    exit_code, _output, raw = _empty_fs_report(tmp_path, "-f", "sarif")
    properties = json.loads(raw)["runs"][0]["properties"]
    assert exit_code == 0
    assert properties["posture_grade"] == "N/A"
    assert properties["scan_outcome"] == "partial"


@pytest.mark.parametrize("fmt", ["markdown", "html"])
def test_empty_directory_rendered_reports_do_not_grade(tmp_path, fmt):
    exit_code, _output, raw = _empty_fs_report(tmp_path, "-f", fmt)
    assert exit_code == 0
    assert "Nothing to scan" in raw
    assert ">A<" not in raw
    assert "grade: A" not in raw.lower()


def test_directory_with_packages_keeps_a_grade():
    server = MCPServer(name="fs:x", packages=[Package(name="requests", version="2.32.3", ecosystem="pypi")])
    server.surface = _surface("FILESYSTEM")
    report = AIBOMReport(
        agents=[Agent(name="filesystem:x", agent_type=AgentType.CUSTOM, config_path="/x", mcp_servers=[server])], blast_radii=[]
    )
    assert compute_posture_scorecard(report).grade != "N/A"


def _surface(name: str):
    from agent_bom.models import ServerSurface

    return ServerSurface[name]


@pytest.mark.parametrize("surface", ["FILESYSTEM", "CONTAINER_IMAGE", "OCI_TARBALL", "OS_PACKAGES", "SBOM"])
def test_empty_scan_carrier_is_not_evidence(surface):
    server = MCPServer(name="carrier")
    server.surface = _surface(surface)
    report = AIBOMReport(agents=[Agent(name="c", agent_type=AgentType.CUSTOM, config_path="/x", mcp_servers=[server])], blast_radii=[])
    card = compute_posture_scorecard(report)
    assert card.grade == "N/A"
    assert card.no_data is True


def test_a_configured_mcp_server_with_no_packages_is_still_evidence():
    server = MCPServer(name="srv", command="npx")
    report = AIBOMReport(agents=[Agent(name="a", agent_type=AgentType.CUSTOM, config_path="/x", mcp_servers=[server])], blast_radii=[])
    assert compute_posture_scorecard(report).grade != "N/A"


def test_api_empty_filesystem_says_nothing_was_found(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_API_LOCAL_PATH_SCANS", "enabled")
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", _store)
    job = ScanJob(job_id="fs-empty", created_at="2026-11-06T00:00:00Z", request=ScanRequest(filesystem_paths=[str(tmp_path)], enrich=False))
    _run_scan_sync(job)
    assert job.status == JobStatus.DONE
    assert job.result.get("posture_grade") in (None, "N/A")
    assert any("Nothing to scan" in warning for warning in job.result["warnings"])


# ── D9: unreachable target, unknown package ──────────────────────────────────


class _Store:
    retains_job_objects_in_memory = True

    def put(self, job):
        pass


def _store():
    return _Store()


def test_api_scan_of_an_unreachable_only_image_fails_the_job(monkeypatch):
    """Real pipeline and real image scanner: the server egress policy refuses ``.invalid``."""
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", _store)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [])
    job = ScanJob(
        job_id="img-gone", created_at="2026-11-06T00:00:00Z", request=ScanRequest(images=["doesnotexist.invalid/x:1"], enrich=False)
    )
    _run_scan_sync(job)
    assert job.status == JobStatus.FAILED
    assert job.error and "doesnotexist.invalid" in job.error
    assert job.result["status"] == "failed"
    assert job.result["scan_run"]["outcome"] == "failed"
    assert job.result["scan_run"]["issues"][0]["code"] == "collector_failed"


def test_one_unreachable_image_of_two_is_partial_not_failed(monkeypatch):
    def scan_image(image_ref, *, server_context):
        if "invalid" in image_ref:
            raise RuntimeError("registry unreachable")
        return [Package(name="openssl", version="3.0.16", ecosystem="deb")], "native"

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", _store)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda *_a, **_k: None)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [])
    monkeypatch.setattr("agent_bom.image.scan_image", scan_image)
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda *a, **k: [])
    job = ScanJob(
        job_id="img-mixed",
        created_at="2026-11-06T00:00:00Z",
        request=ScanRequest(images=["good.example/app:1", "gone.invalid/app:1"], enrich=False),
    )
    _run_scan_sync(job)
    assert job.status == JobStatus.DONE
    assert job.error is None
    assert job.result["scan_run"]["outcome"] == "partial"


def test_a_scan_with_nothing_requested_is_not_a_failure(monkeypatch):
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", _store)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [])
    job = ScanJob(job_id="none", created_at="2026-11-06T00:00:00Z", request=ScanRequest(enrich=False))
    _run_scan_sync(job)
    assert job.status == JobStatus.DONE
    assert job.result["status"] == "no_agents_found"
    assert job.result["scan_run"]["outcome"] == "complete"


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code

    def json(self) -> dict:
        return {"info": {"name": "x", "summary": "s"}}


class _Client:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def get(self, *_args, **_kwargs):
        return _Response(self.status_code)


@pytest.mark.parametrize("ecosystem", ["pypi", "npm"])
@pytest.mark.parametrize("status,expected", [(404, True), (500, False), (429, False), (200, False)])
def test_only_a_registry_404_marks_a_package_as_not_found(monkeypatch, ecosystem, status, expected):
    from agent_bom.autodiscover import enrich_unknown_packages

    monkeypatch.setattr("agent_bom.http_client.create_client", lambda **_k: _Client(status))
    pkg = Package(name="zzzz-not-real-pkg-xyz", version="1.0.0", ecosystem=ecosystem)
    asyncio.run(enrich_unknown_packages([pkg]))
    assert pkg.registry_not_found is expected


def _fake_package_scan(monkeypatch, tmp_path: Path, *args: str):
    (tmp_path / "requirements.txt").write_text("zzzz-not-real-pkg-xyz==1.0.0\n")

    async def no_lookup(*_a, **_k):
        return {}

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", no_lookup)
    monkeypatch.setattr("agent_bom.http_client.create_client", lambda **_k: _Client(404))
    return CliRunner().invoke(main, ["fs", str(tmp_path), *args])


def test_package_not_on_registry_is_named_instead_of_clean(monkeypatch, tmp_path):
    result = _fake_package_scan(monkeypatch, tmp_path, "-f", "console")
    output = _flat(result.output)
    assert "supply chain looks clean" not in output
    assert "not found on its public registry" in output
    assert "zzzz-not-real-pkg-xyz@1.0.0" in output
    assert "Posture grade: A" not in output
    assert result.exit_code == 0, output


def test_package_not_on_registry_is_recorded_in_the_report(monkeypatch, tmp_path):
    artifact = tmp_path / "r.json"
    result = _fake_package_scan(monkeypatch, tmp_path, "-f", "json", "-o", str(artifact))
    report = json.loads(artifact.read_text())
    assert result.exit_code == 0, result.output
    issue = next(i for i in report["scan_run"]["issues"] if i["code"] == "package_not_on_registry")
    assert issue["affects_coverage"] is False
    assert "zzzz-not-real-pkg-xyz@1.0.0" in issue["message"]
    assert report["posture_grade"] == "N/A"
    rows = [p for a in report["agents"] for s in a["mcp_servers"] for p in s["packages"]]
    assert rows and rows[0]["registry_not_found"] is True


def test_posture_summary_panel_does_not_call_a_missing_package_clean(monkeypatch):
    from rich.console import Console

    from agent_bom.cli.agents import _posture

    capture = Console(record=True, width=200)
    monkeypatch.setattr(_posture, "Console", lambda: capture)
    pkg = Package(name="ghost", version="1", ecosystem="pypi", registry_not_found=True)
    agent = Agent(name="a", agent_type=AgentType.CUSTOM, config_path="/x", mcp_servers=[MCPServer(name="s", packages=[pkg])])
    _posture.render_posture_summary([agent], [])
    text = capture.export_text()
    assert "looks clean" not in text
    assert "not found on its public registry" in text
