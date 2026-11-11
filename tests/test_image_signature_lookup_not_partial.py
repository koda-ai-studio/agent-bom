"""A failed signature/referrer lookup is missing provenance, not missing package coverage.

Docker Engine 29's containerd image store gives a locally built, never-pushed
image a ``RepoDigests`` entry, so a scan of ``app:local`` now asks Docker Hub
for signatures of a repository that does not exist and gets HTTP 401. The
packages were still extracted and scanned, so the run must stay complete:
signature status stays ``unknown`` and ``--require-signature`` still fails.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx

from agent_bom.coverage import is_scan_note
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.image_evidence.model import ImageEvidence
from agent_bom.image_evidence.surfaces import signature_policy_violation
from agent_bom.oci_registry.client import RegistryClient
from agent_bom.oci_registry.reference import parse_reference
from agent_bom.oci_registry.supply_chain import discover_supply_chain
from agent_bom.scanners.state import consume_coverage_warnings

SUBJECT = "sha256:" + "c" * 64


def _unauthorized_lookup() -> tuple[ImageEvidence, list[dict]]:
    consume_coverage_warnings()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(401)

    evidence = ImageEvidence("agent-bom:latest-refresh-test", digest=SUBJECT)
    client = RegistryClient(parse_reference("docker.io/library/agent-bom@" + SUBJECT), transport=httpx.MockTransport(handler))
    with client:
        discover_supply_chain(client, evidence, None)
    assert seen, "the lookup must actually reach the registry for this test to mean anything"
    return evidence, consume_coverage_warnings()


def test_unauthorized_referrers_keep_signature_unknown_and_record_a_note():
    evidence, warnings = _unauthorized_lookup()

    assert evidence.signature["status"] == "unknown"
    assert evidence.signature["detail"].startswith("Signature lookup failed:")
    supply = [w for w in warnings if w.get("reason") == "image_supply_chain_incomplete"]
    assert len(supply) == 1
    assert is_scan_note(supply[0])
    assert "not evidence of an unsigned image" in supply[0]["detail"]


def test_failed_signature_lookup_does_not_make_the_package_scan_partial():
    _evidence, warnings = _unauthorized_lookup()

    run = effective_scan_run(SimpleNamespace(coverage_warnings=warnings, scan_run=None))

    assert run.outcome is ScanOutcome.COMPLETE
    notes = [issue for issue in run.issues if issue.code == "scan_note"]
    assert len(notes) == 1
    assert notes[0].affects_coverage is False
    assert "signature/referrer discovery did not complete" in notes[0].message


def test_require_signature_still_fails_when_the_lookup_failed(tmp_path):
    evidence, _warnings = _unauthorized_lookup()
    evidence.cosign_key_path = str(tmp_path / "cosign.pub")

    violation = signature_policy_violation(evidence, True)

    assert violation is not None
    assert "unknown" in violation
    assert signature_policy_violation(evidence, False) is None


def test_genuine_package_coverage_gaps_still_make_the_scan_partial():
    gap = {
        "ecosystem": "generic",
        "release": "node:24.15.0",
        "reason": "runtime_advisory_coverage_unknown",
        "detail": "Vulnerability coverage for node 24.15.0 is unknown.",
        "package_count": 1,
        "advisory_rows": 0,
    }
    _evidence, warnings = _unauthorized_lookup()

    run = effective_scan_run(SimpleNamespace(coverage_warnings=[*warnings, gap], scan_run=None))

    assert run.outcome is ScanOutcome.PARTIAL
    assert [issue.code for issue in run.issues if issue.affects_coverage] == ["vulnerability_coverage_gap"]
