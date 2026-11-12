"""The image refresh gate accepts only reviewed, exact, unexpired coverage gaps.

A runtime no advisory source agent-bom consults tracks leaves an image scan
honestly ``partial``. The gate may accept such a gap only when it is listed in
``docs/security/image-exceptions.yaml``; any other coverage gap, an expired or
mismatched exception, or a blocking finding must still fail. The fixtures use a
Node.js gap as the shape of such a report.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_image_coverage_exceptions.py"
IMAGE = "agentbom/agent-bom-ui"
TODAY = date(2026, 11, 11)
NODE_DETAIL = (
    "Vulnerability coverage for node 24.15.0 is unknown: it has no OSV ecosystem and no advisory source this scan "
    "consulted tracks it (the local advisory DB holds no CPE ranges for it). It was not assessed, so zero findings "
    "is not a clean bill of health."
)


def _module():
    spec = importlib.util.spec_from_file_location("check_image_coverage_exceptions", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _exception(**overrides) -> dict:
    entry = {
        "id": "ui-node-runtime-advisory-source",
        "reason_code": "runtime_advisory_coverage_unknown",
        "release": "node:24.15.0",
        "images": [IMAGE],
        "owner": "maintainers",
        "status": "temporary_exception",
        "reason": "No advisory source tracks the Node.js runtime binary.",
        "opened_at": "2026-11-11",
        "review_after": "2026-12-11",
        "expires_at": "2027-01-11",
        "remove_when": "Remove when the runtime is assessed.",
    }
    entry.update(overrides)
    return entry


def _report(*, release: str = "node:24.15.0", detail: str = NODE_DETAIL, outcome: str = "partial") -> dict:
    """The shape the scanner writes for the refresh UI image (taken from a real run)."""
    return {
        "scan_run": {
            "outcome": outcome,
            "issues": [
                {"code": "scanner_warning", "source": "vulnerability-data", "message": detail, "affects_coverage": True},
                {"code": "vulnerability_coverage_gap", "source": "generic", "message": f"{release}: {detail}", "affects_coverage": True},
                {"code": "scan_note", "source": "oci", "message": "oci-note:x: signature lookup", "affects_coverage": False},
            ],
            "scopes": [],
        },
        "coverage_warnings": [
            {"ecosystem": "generic", "release": release, "reason": "runtime_advisory_coverage_unknown", "detail": detail},
        ],
        "blast_radius": [],
        "findings": [],
        "packages": [],
    }


def _check(report: dict, exceptions: list[dict], tmp_path: Path, image: str = IMAGE) -> list[str]:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report))
    registry = tmp_path / "image-exceptions.yaml"
    registry.write_text(yaml.safe_dump({"exceptions": [], "coverage_exceptions": exceptions}))
    return _module().gate_failures(report_path, registry, image=image, today=TODAY, fail_on_severity="medium")


def test_reviewed_node_runtime_gap_is_the_only_partial_cause_and_passes(tmp_path):
    assert _check(_report(), [_exception()], tmp_path) == []


def test_no_exception_means_the_partial_scan_still_fails(tmp_path):
    failures = _check(_report(), [], tmp_path)
    assert failures and any("node:24.15.0" in failure for failure in failures)


def test_any_other_coverage_gap_still_fails(tmp_path):
    report = _report()
    report["scan_run"]["issues"].append(
        {
            "code": "vulnerability_coverage_gap",
            "source": "vulnerability-data",
            "message": "local-vuln-db:untrusted: stale",
            "affects_coverage": True,
        }
    )
    failures = _check(report, [_exception()], tmp_path)
    assert len(failures) == 1
    assert "local-vuln-db:untrusted" in failures[0]


def test_the_exception_is_pinned_to_the_exact_runtime_version(tmp_path):
    detail = NODE_DETAIL.replace("24.15.0", "24.16.0")
    failures = _check(_report(release="node:24.16.0", detail=detail), [_exception()], tmp_path)
    assert failures and all("node:24.16.0" in failure or "24.16.0" in failure for failure in failures)


def test_an_expired_exception_is_not_accepted(tmp_path):
    failures = _check(_report(), [_exception(expires_at="2026-11-10")], tmp_path)
    assert any("expired" in failure for failure in failures)


def test_an_exception_for_another_image_does_not_apply(tmp_path):
    failures = _check(_report(), [_exception(images=["agentbom/agent-bom"])], tmp_path)
    assert failures


@pytest.mark.parametrize("severity", ["medium", "high", "critical", "unknown"])
def test_an_active_vulnerability_at_the_gate_still_fails(tmp_path, severity):
    report = _report()
    report["blast_radius"] = [{"vulnerability_id": "CVE-2026-0001", "severity": severity, "suppressed": False}]
    failures = _check(report, [_exception()], tmp_path)
    assert any("CVE-2026-0001" in failure for failure in failures)


def test_suppressed_or_below_gate_vulnerabilities_do_not_fail(tmp_path):
    report = _report()
    report["blast_radius"] = [
        {"vulnerability_id": "CVE-2026-0002", "severity": "high", "suppressed": True},
        {"vulnerability_id": "CVE-2026-0003", "severity": "low", "suppressed": False},
    ]
    assert _check(report, [_exception()], tmp_path) == []


def test_malicious_packages_and_blocking_non_cve_findings_still_fail(tmp_path):
    report = _report()
    report["packages"] = [{"name": "evil", "version": "1.0", "is_malicious": True}]
    report["findings"] = [
        {"finding_type": "SECRET", "severity": "high", "suppressed": False, "id": "secret-1"},
        {"finding_type": "CVE", "severity": "critical", "suppressed": False, "id": "cve-row"},
    ]
    failures = _check(report, [_exception()], tmp_path)
    assert any("evil" in failure for failure in failures)
    assert any("SECRET" in failure for failure in failures)
    assert not any("cve-row" in failure for failure in failures), "CVE rows are gated through blast_radius, after exclusions"


@pytest.mark.parametrize("outcome", ["complete", "failed"])
def test_only_a_partial_outcome_can_be_accepted(tmp_path, outcome):
    failures = _check(_report(outcome=outcome), [_exception()], tmp_path)
    assert any(outcome in failure for failure in failures)


def test_incomplete_requested_scope_still_fails(tmp_path):
    report = _report()
    report["scan_run"]["scopes"] = [{"name": "image", "requested": True, "status": "partial"}]
    assert any("image" in failure for failure in _check(report, [_exception()], tmp_path))


def test_malformed_report_fails_closed(tmp_path):
    assert _check({"findings": []}, [_exception()], tmp_path)


def test_cli_exit_codes(tmp_path, capsys):
    module = _module()
    report_path = tmp_path / "report.json"
    registry = tmp_path / "image-exceptions.yaml"
    registry.write_text(yaml.safe_dump({"coverage_exceptions": [_exception(expires_at="2999-01-01")]}))
    report_path.write_text(json.dumps(_report()))
    argv = ["--report", str(report_path), "--exceptions", str(registry), "--image", IMAGE, "--fail-on-severity", "medium"]
    assert module.main(argv) == 0
    assert "accepted" in capsys.readouterr().out
    report_path.write_text(json.dumps(_report(release="node:99.0.0", detail="other")))
    assert module.main(argv) == 1


def test_committed_coverage_exceptions_are_reviewed_and_bounded():
    data = yaml.safe_load((ROOT / "docs" / "security" / "image-exceptions.yaml").read_text())
    entries = data.get("coverage_exceptions")
    assert isinstance(entries, list), "coverage_exceptions stays a list, empty when no gap is accepted"
    # Node.js runtimes have their own advisory source, so a Node.js gap is a real failure to fix, not to accept.
    assert not [entry for entry in entries if str(entry.get("release", "")).startswith("node:")]
    required = {
        "id",
        "reason_code",
        "release",
        "images",
        "owner",
        "status",
        "reason",
        "opened_at",
        "review_after",
        "expires_at",
        "remove_when",
    }
    for entry in entries:
        assert required <= set(entry), entry.get("id")
        assert entry["reason_code"] == "runtime_advisory_coverage_unknown"
        assert ":" in entry["release"] and "*" not in entry["release"], "exceptions name one exact runtime version"
        opened, expires = date.fromisoformat(str(entry["opened_at"])), date.fromisoformat(str(entry["expires_at"]))
        assert opened <= date.fromisoformat(str(entry["review_after"])) <= expires
        assert (expires - opened).days <= 92, "coverage exceptions must be re-reviewed at least quarterly"
