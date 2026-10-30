"""Lake snapshots enter the existing report/graph path without fabricated coverage."""

from __future__ import annotations

import json
import stat

import pytest
from click.testing import CliRunner

from agent_bom.cli._ingest_group import ingest_group


def fixture():
    mapping = {
        "schema_version": "agent-bom.lake-mapping/v1",
        "provider": "aws-security-lake",
        "source_instance": "sample-lake/security-findings",
        "exported_at": "2026-10-30T00:00:00Z",
        "finding_type": "CLOUD_BEST_PRACTICE_FAIL",
        "asset_type": "cloud_resource",
        "columns": {"finding_id": "/finding_info/uid", "asset_id": "/resources/0/uid", "title": "/finding_info/title"},
        "severity_values": {"4": "high"},
    }
    rows = [
        {
            "finding_info": {"uid": "finding-one", "title": "Public bucket"},
            "resources": [{"uid": "bucket-one"}],
            "severity": 4,
            "observed_at": "2026-10-29T23:00:00Z",
            "provider": "aws",
            "account_id": "sample-account-one",
            "region": "us-east-1",
            "controls": [{"framework": "cis", "control": "2.1", "version": "3.0"}],
            "private_password": "not-for-output",
            "graph_reachable": True,
        }
    ]
    return rows, mapping


def test_cli_lake_produces_private_report_for_existing_push(tmp_path):
    rows, mapping = fixture()
    source, config, output = [tmp_path / name for name in ("rows.json", "mapping.json", "report.json")]
    source.write_text(json.dumps(rows))
    config.write_text(json.dumps(mapping))
    args = ["lake", str(source), "--mapping", str(config), "-o", str(output)]
    result = CliRunner().invoke(ingest_group, args)
    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text())
    assert len(report["findings"]) == 1
    assert report["findings"][0]["severity"] == "high"
    assert report["findings"][0]["account_ref"] == "aws:sample-account-one"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    original = output.read_bytes()
    assert CliRunner().invoke(ingest_group, args).exit_code != 0
    assert output.read_bytes() == original


def build(rows=None, mapping=None):
    from agent_bom.parsers.lake_evidence import build_lake_report

    defaults = fixture()
    return build_lake_report(rows if rows is not None else defaults[0], mapping or defaults[1], artifact_sha256="a" * 64)


def test_receipts_preserve_scope_time_controls_but_not_unmapped_or_claimed_reach():
    report = build()
    row = report["findings"][0]
    assert row["first_seen"] == "2026-10-29T23:00:00+00:00"
    assert row["evidence"]["lake_receipt"]["artifact_sha256"] == "a" * 64
    assert row["evidence"]["lake_receipt"]["collection_coverage"] == "unknown"
    assert row["evidence"]["lake_receipt"]["execution"] == "not_established"
    assert row["controls"][0]["source"] == "lake:source_declared"
    assert row["graph_reachable"] is None
    assert "not-for-output" not in json.dumps(report)
    assert report["coverage_warnings"]


def test_identity_stable_on_replay_and_separate_across_accounts_and_sources():
    first = build()
    assert first == build()
    rows, mapping = fixture()
    rows[0]["account_id"] = "sample-account-two"
    assert first["findings"][0]["id"] != build(rows)["findings"][0]["id"]
    mapping["source_instance"] = "different-lake"
    assert first["source_id"] != build(mapping=mapping)["source_id"]


@pytest.mark.parametrize(
    "change", ["empty", "duplicate", "missing_scope", "naive_time", "future_row", "unknown_kind", "too_many", "bad_control"]
)
def test_invalid_snapshot_fails_before_artifact(change):
    rows, mapping = fixture()
    if change == "empty":
        rows = []
    elif change == "duplicate":
        rows *= 2
    elif change == "missing_scope":
        del rows[0]["account_id"]
    elif change == "naive_time":
        rows[0]["observed_at"] = "2026-10-29T23:00:00"
    elif change == "future_row":
        rows[0]["observed_at"] = "2026-11-01T00:00:00Z"
    elif change == "unknown_kind":
        mapping["finding_type"] = "clean"
    elif change == "too_many":
        rows *= 1001
    elif change == "bad_control":
        rows[0]["controls"][0]["attested"] = True
    with pytest.raises(ValueError):
        build(rows, mapping)


def test_report_builds_nonempty_graph_and_keeps_recorded_association():
    from agent_bom.api.models import PushPayload
    from agent_bom.api.push_evidence import normalize_pushed_report
    from agent_bom.graph.builder import build_unified_graph_from_report

    report = normalize_pushed_report(PushPayload.model_validate(build()), fallback_scan_id="lake-test")
    graph = build_unified_graph_from_report(report, scan_id="lake-test", tenant_id="tenant-one")
    assert len(graph.nodes) >= 2
    assert graph.edges
    assert any(n.label == "Public bucket" for n in graph.nodes.values())
    assert any(n.attributes.get("account_id") == "aws:sample-account-one" for n in graph.nodes.values())


def test_cli_rejects_bad_batch_without_partial_output(tmp_path):
    rows, mapping = fixture()
    rows.append({"private_password": "do-not-echo"})
    source, config, output = [tmp_path / name for name in ("rows.json", "mapping.json", "report.json")]
    source.write_text(json.dumps(rows))
    config.write_text(json.dumps(mapping))
    result = CliRunner().invoke(ingest_group, ["lake", str(source), "--mapping", str(config), "-o", str(output)])
    assert result.exit_code != 0
    assert not output.exists()
    assert "do-not-echo" not in result.output


def test_same_named_cloud_assets_stay_separate_across_accounts_and_regions():
    from copy import deepcopy

    from agent_bom.graph.builder import build_unified_graph_from_report

    rows, mapping = fixture()
    second = deepcopy(rows[0])
    second["account_id"] = "sample-account-two"
    third = deepcopy(rows[0])
    third["region"] = "us-west-2"
    report = build([*rows, second, third], mapping)
    graph = build_unified_graph_from_report(report, scan_id="lake-scope", tenant_id="tenant-one")
    resources = [n for n in graph.nodes.values() if n.entity_type.value == "cloud_resource"]
    assert len(resources) == 3
    assert len({f["id"] for f in report["findings"]}) == 3
    assert len({f["node_id"] for f in report["findings"]}) == 3


def test_push_preserves_explicit_replay_key_and_source(monkeypatch, tmp_path):
    import agent_bom.push as push

    rows, mapping = fixture()
    source, config, output = [tmp_path / name for name in ("rows.json", "mapping.json", "report.json")]
    source.write_text(json.dumps(rows))
    config.write_text(json.dumps(mapping))
    monkeypatch.setenv("AGENT_BOM_PUSH_API_KEY", "test-" + "placeholder")
    called = []

    def capture(url, report, api_key, **kwargs):
        called.append((url, push.sanitize_results(report, **kwargs)))
        return {"job_id": "sample-job"}

    monkeypatch.setattr("agent_bom.cli._lake_ingest.push_json", capture)
    result = CliRunner().invoke(
        ingest_group, ["lake", str(source), "--mapping", str(config), "-o", str(output), "--push", "https://cp.example.com"]
    )
    assert result.exit_code == 0, result.output
    saved = json.loads(output.read_text())
    assert called[0][0] == "https://cp.example.com/v1/results/push"
    assert called[0][1]["idempotency_key"] == saved["idempotency_key"]
    assert called[0][1]["source_id"] == saved["source_id"]


def test_push_failure_retains_report_and_does_not_echo_credentials(monkeypatch, tmp_path):

    rows, mapping = fixture()
    source, config, output = [tmp_path / name for name in ("rows.json", "mapping.json", "report.json")]
    source.write_text(json.dumps(rows))
    config.write_text(json.dumps(mapping))
    monkeypatch.setenv("AGENT_BOM_PUSH_API_KEY", "test-" + "placeholder")
    monkeypatch.setattr("agent_bom.cli._lake_ingest.push_json", lambda *a, **kw: None)
    result = CliRunner().invoke(
        ingest_group, ["lake", str(source), "--mapping", str(config), "-o", str(output), "--push", "https://cp.example.com"]
    )
    assert result.exit_code == 1 and output.exists()
    assert "placeholder" not in result.output


def test_package_occurrences_remain_scoped_and_times_normalize_to_utc():
    from copy import deepcopy

    rows, mapping = fixture()
    mapping.update(asset_type="package", finding_type="CVE")
    rows[0]["resources"][0]["uid"] = "pkg:pypi/sample@1.0"
    rows[0]["observed_at"] = "2026-10-29T19:00:00-04:00"
    other = deepcopy(rows[0])
    other["account_id"] = "sample-account-two"
    report = build([*rows, other], mapping)
    assert len({r["id"] for r in report["findings"]}) == 2
    assert report["observed_at"] == "2026-10-29T23:00:00+00:00"


def test_ocfs_style_millisecond_observation_is_explicit_and_stable():
    rows, mapping = fixture()
    mapping["timestamp_format"] = "unix_ms"
    rows[0]["observed_at"] = 0
    assert build(rows, mapping)["observed_at"] == "1970-01-01T00:00:00+00:00"
    rows[0]["observed_at"] = True
    with pytest.raises(ValueError):
        build(rows, mapping)


def test_s3_receipt_survives_client_and_server_sanitization():
    from agent_bom.api.models import PushPayload
    from agent_bom.api.push_evidence import normalize_pushed_report
    from agent_bom.parsers.lake_evidence import build_lake_report
    from agent_bom.push import sanitize_results

    rows, mapping = fixture()
    receipt = {
        "kind": "s3_object",
        "bucket": "sample-lake",
        "object_path": "exports/findings.json",
        "version_id": "v1",
        "owner": "123456789012",
    }
    report = build_lake_report(rows, mapping, artifact_sha256="a" * 64, object_receipt=receipt)
    sanitized = sanitize_results(report, source_id=report["source_id"], idempotency_key=report["idempotency_key"])
    persisted = normalize_pushed_report(PushPayload.model_validate(sanitized), fallback_scan_id="lake-test")
    assert persisted["findings"][0]["evidence"]["lake_receipt"]["object"] == receipt
