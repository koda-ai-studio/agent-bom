"""Installed metadata comparisons must never turn missing evidence into a fix."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.evidence.package_remediation import capture_package, compare_packages

NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
ADVISORY = {
    "id": "EXAMPLE-2026-1",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "example-package"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
        }
    ],
}


def install(root, version, directory="example_package.dist-info"):
    dist = root / directory
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(f"Metadata-Version: 2.1\nName: example-package\nVersion: {version}\n")
    return dist


def capture(root, advisory=None, when=NOW, tenant="tenant-a"):
    return capture_package(root, package="example-package", tenant_id=tenant, advisory=advisory or ADVISORY, now=when)


def pair(tmp_path):
    install(tmp_path, "1.0")
    before = capture(tmp_path)
    install(tmp_path, "2.0")
    return before, capture(tmp_path, when=NOW + timedelta(minutes=1))


def compare(before, after, **kwargs):
    return compare_packages(before, after, now=NOW + timedelta(minutes=2), **kwargs)


def test_installed_update_retains_exact_receipts_and_bounded_claim(tmp_path):
    before, after = pair(tmp_path)
    result = compare(before, after)
    assert result["outcome"] == "verified_for_selected_advisory"
    assert result["claim_scope"] == "installed_distribution_metadata"
    assert result["before_digest"] == before["digest"]
    assert result["after_digest"] == after["digest"]
    assert result["independently_verified"] is False
    assert result["runtime_loaded_version_verified"] is False
    assert result["baseline_version"] == "1.0"
    assert result["candidate_version"] == "2.0"
    assert result["fixed_versions"] == ["2.0"]


def test_unchanged_affected_version_is_not_fixed(tmp_path):
    install(tmp_path, "1.0")
    before = capture(tmp_path)
    after = capture(tmp_path, when=NOW + timedelta(minutes=1))
    assert compare(before, after)["outcome"] == "still_affected"


def test_disappeared_package_is_unknown(tmp_path):
    dist = install(tmp_path, "1.0")
    before = capture(tmp_path)
    (dist / "METADATA").unlink()
    after = capture(tmp_path, when=NOW + timedelta(minutes=1))
    assert compare(before, after)["outcome"] == "unavailable_evidence"


def test_duplicate_installations_are_unknown(tmp_path):
    before, _ = pair(tmp_path)
    install(tmp_path, "1.0", "duplicate.dist-info")
    after = capture(tmp_path, when=NOW + timedelta(minutes=1))
    assert compare(before, after)["outcome"] == "unavailable_evidence"


@pytest.mark.parametrize("mutation", ["tenant", "directory", "advisory", "stale", "replay", "tamper"])
def test_noncomparable_evidence_cannot_verify(tmp_path, mutation):
    before, after = pair(tmp_path)
    if mutation == "tenant":
        after = capture(tmp_path, tenant="tenant-b", when=NOW + timedelta(minutes=1))
    elif mutation == "directory":
        other = tmp_path / "other"
        install(other, "2.0")
        after = capture(other, when=NOW + timedelta(minutes=1))
    elif mutation == "advisory":
        advisory = deepcopy(ADVISORY)
        advisory["summary"] = "changed advisory"
        after = capture(tmp_path, advisory, NOW + timedelta(minutes=1))
    elif mutation == "stale":
        assert compare(before, after, max_age_seconds=10)["outcome"] == "unavailable_evidence"
        return
    elif mutation == "replay":
        after = before
    else:
        after["package"] = "tampered"
    assert compare(before, after)["outcome"] == "unavailable_evidence"


@pytest.mark.parametrize(
    "ranges",
    [
        [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}],
        [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"limit": "2.0"}]}],
        [{"type": "ECOSYSTEM", "events": []}],
        [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "unknown"}]}],
    ],
)
def test_unsupported_or_nonfix_boundaries_cannot_verify(tmp_path, ranges):
    advisory = deepcopy(ADVISORY)
    advisory["affected"][0]["ranges"] = ranges
    install(tmp_path, "1.0")
    before = capture(tmp_path, advisory)
    install(tmp_path, "2.0")
    after = capture(tmp_path, advisory, NOW + timedelta(minutes=1))
    assert compare(before, after)["outcome"] == "unavailable_evidence"


def test_reintroduced_window_remains_affected(tmp_path):
    advisory = deepcopy(ADVISORY)
    advisory["affected"][0]["ranges"][0]["events"] += [{"introduced": "3.0"}]
    install(tmp_path, "1.0")
    before = capture(tmp_path, advisory)
    install(tmp_path, "3.1")
    after = capture(tmp_path, advisory, NOW + timedelta(minutes=1))
    assert compare(before, after)["outcome"] == "still_affected"


def test_already_unaffected_baseline_is_not_remediation(tmp_path):
    install(tmp_path, "2.0")
    before = capture(tmp_path)
    install(tmp_path, "2.1")
    after = capture(tmp_path, when=NOW + timedelta(minutes=1))
    assert compare(before, after)["outcome"] == "unavailable_evidence"


def test_unrelated_fixed_window_does_not_prove_selected_fix(tmp_path):
    advisory = deepcopy(ADVISORY)
    advisory["affected"][0]["ranges"] = [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.5"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.2"}]},
    ]
    install(tmp_path, "1.0")
    before = capture(tmp_path, advisory)
    install(tmp_path, "2.0")
    after = capture(tmp_path, advisory, NOW + timedelta(minutes=1))
    assert compare(before, after)["outcome"] == "unavailable_evidence"


def test_cli_captures_compares_and_preserves_existing_evidence(tmp_path):
    import json

    from click.testing import CliRunner

    from agent_bom.cli import main

    root = tmp_path / "site-packages"
    install(root, "1.0")
    advisory = tmp_path / "advisory.json"
    advisory.write_text(json.dumps(ADVISORY))
    runner = CliRunner()
    baseline, candidate, proof = (tmp_path / filename for filename in ("before.json", "after.json", "proof.json"))
    command = [
        "verify-remediation",
        "capture",
        "--site-packages",
        str(root),
        "--package",
        "example-package",
        "--tenant-id",
        "tenant-a",
        "--advisory",
        str(advisory),
    ]
    first = runner.invoke(main, [*command, "--output", str(baseline)])
    assert first.exit_code == 0, first.output
    install(root, "2.0")
    second = runner.invoke(main, [*command, "--output", str(candidate)])
    assert second.exit_code == 0, second.output
    result = runner.invoke(
        main, ["verify-remediation", "compare", "--before", str(baseline), "--after", str(candidate), "--output", str(proof)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(proof.read_text())["outcome"] == "verified_for_selected_advisory"
    saved = baseline.read_bytes()
    assert runner.invoke(main, [*command, "--output", str(baseline)]).exit_code != 0
    assert baseline.read_bytes() == saved


@pytest.mark.parametrize(
    "mutation", ["withdrawn", "other_package", "other_ecosystem", "malformed_row", "malformed_versions", "unknown_range"]
)
def test_advisory_uncertainty_never_closes_update(tmp_path, mutation):
    advisory = deepcopy(ADVISORY)
    if mutation == "withdrawn":
        advisory["withdrawn"] = "2026-10-15T00:00:00Z"
    elif mutation == "other_package":
        advisory["affected"][0]["package"]["name"] = "different"
    elif mutation == "other_ecosystem":
        advisory["affected"][0]["package"]["ecosystem"] = "npm"
    elif mutation == "malformed_row":
        advisory["affected"].append(None)
    elif mutation == "malformed_versions":
        advisory["affected"][0]["versions"] = "1.0"
    else:
        advisory["affected"][0]["ranges"].append({"type": "GIT", "events": [{"introduced": "0"}]})
    install(tmp_path, "1.0")
    before = capture(tmp_path, advisory)
    install(tmp_path, "2.0")
    after = capture(tmp_path, advisory, NOW + timedelta(minutes=1))
    assert compare(before, after)["outcome"] == "unavailable_evidence"


@pytest.mark.parametrize("layout", ["symlink", "duplicate_header", "invalid_version", "legacy"])
def test_unreliable_metadata_is_unavailable(tmp_path, layout):
    before, _ = pair(tmp_path)
    dist = tmp_path / "example_package.dist-info"
    if layout == "symlink":
        target = tmp_path / "original"
        (dist / "METADATA").rename(target)
        (dist / "METADATA").symlink_to(target)
    elif layout == "duplicate_header":
        with (dist / "METADATA").open("a") as stream:
            stream.write("Version: 3.0\n")
    elif layout == "invalid_version":
        install(tmp_path, "not-a-version")
    else:
        (tmp_path / "legacy.egg-info").mkdir()
    after = capture(tmp_path, when=NOW + timedelta(minutes=1))
    assert after["collection_status"] == "unavailable"
    assert compare(before, after)["outcome"] == "unavailable_evidence"


def test_future_collection_and_invalid_policy_fail_closed(tmp_path):
    before, after = pair(tmp_path)
    assert compare_packages(before, after, now=NOW)["outcome"] == "unavailable_evidence"
    with pytest.raises(ValueError):
        compare(before, after, max_age_seconds=0)


def test_cli_non_success_outcomes_retain_receipts(tmp_path):
    import json

    from click.testing import CliRunner

    from agent_bom.cli import main

    before, _ = pair(tmp_path)
    # Use current collection times for the real command's freshness checks.
    install(tmp_path, "1.0")
    before = capture_package(tmp_path, package="example-package", tenant_id="tenant-a", advisory=ADVISORY)
    after = capture_package(tmp_path, package="example-package", tenant_id="tenant-a", advisory=ADVISORY)
    baseline, candidate = tmp_path / "before.json", tmp_path / "after.json"
    baseline.write_text(json.dumps(before))
    candidate.write_text(json.dumps(after))
    runner = CliRunner()
    command = ["verify-remediation", "compare", "--before", str(baseline), "--after", str(candidate)]
    proof = tmp_path / "still-affected.json"
    assert runner.invoke(main, [*command, "--output", str(proof)]).exit_code == 1
    assert json.loads(proof.read_text())["outcome"] == "still_affected"
    after["scope_id"] = "edited"
    candidate.write_text(json.dumps(after))
    proof = tmp_path / "unknown.json"
    assert runner.invoke(main, [*command, "--output", str(proof)]).exit_code == 2
    assert json.loads(proof.read_text())["reason_codes"] == ["receipt_invalid"]
    saved = proof.read_bytes()
    assert runner.invoke(main, [*command, "--output", str(proof)]).exit_code != 0
    assert proof.read_bytes() == saved
    candidate.write_text('{"digest":"one","digest":"two"}')
    rejected = tmp_path / "rejected.json"
    assert runner.invoke(main, [*command, "--output", str(rejected)]).exit_code != 0
    assert not rejected.exists()


def test_collection_budget_retains_unavailable_receipt(tmp_path, monkeypatch):
    import agent_bom.evidence.package_remediation as verification

    install(tmp_path, "1.0")
    (tmp_path / "another-entry").mkdir()
    monkeypatch.setattr(verification, "MAX_ENTRIES", 1)
    receipt = capture(tmp_path)
    assert receipt["collection_status"] == "unavailable"
    assert "collection_budget_exhausted" in receipt["reason_codes"]


def test_crlf_metadata_is_stable_and_preserved(tmp_path):
    dist = install(tmp_path, "1.0")
    raw = (dist / "METADATA").read_bytes().replace(b"\n", b"\r\n")
    (dist / "METADATA").write_bytes(raw)
    receipt = capture(tmp_path)
    assert receipt["collection_status"] == "complete"
    assert receipt["observations"][0]["metadata"].encode() == raw
