"""A leadership brief must preserve scope, distinct identities and missing evidence."""

import json
from copy import deepcopy

import pytest
from click.testing import CliRunner

from agent_bom.output.impact_brief import build_impact_brief
from agent_bom.output.impact_html import render_impact_brief


def scan(scan_id="after", day=17):
    return {
        "document_type": "AI-BOM",
        "schema_version": "1.0",
        "canonical_id_schema_version": "3",
        "scan_id": scan_id,
        "generated_at": f"2026-10-{day}T12:00:00Z",
        "tenant_id": "example",
        "scan_sources": ["agent_discovery"],
        "scan_run": {"outcome": "complete", "scopes": [{"name": "example", "requested": True, "status": "complete"}]},
        "findings": [finding()],
        "exposure_paths": {"paths": []},
    }


def finding(identifier="f1", asset="a1", agent="agent:scope:one"):
    return {
        "id": identifier,
        "occurrence_id": identifier,
        "finding_group_id": "group-one",
        "asset": {"canonical_id": asset, "name": "same-name", "asset_type": "mcp_server"},
        "title": "Example vulnerable dependency",
        "severity": "high",
        "finding_type": "CVE",
        "description": "A reported condition requiring applicability review.",
        "remediation_guidance": "Update the affected dependency, then rescan.",
        "match_confidence_tier": "osv_range",
        "evidence": {"agent_server_links": [{"agent_ref": agent, "server_ref": "server:" + asset}]},
    }


def test_unique_assets_occurrences_groups_and_paths_are_separate():
    doc = scan()
    doc["findings"] += [deepcopy(doc["findings"][0]), finding("f2", "a2", "agent:scope:two")]
    doc["exposure_paths"]["paths"] = [{"id": "path-one"}, {"id": "path-one"}]
    result = build_impact_brief(doc)
    assert result["current"]["counts"] == {
        "finding_rows": 3,
        "finding_occurrences": 2,
        "finding_groups": 1,
        "asset_ids": 2,
        "agent_ids": 2,
        "recorded_paths": 1,
        "occurrences_without_asset_id": 0,
        "occurrences_without_agent_id": 0,
        "occurrences_without_group_id": 0,
    }
    assert len(result["current"]["priorities"]) == 2
    assert result["current"]["priorities"][0]["receipt_pointer"] == "/findings/0"


def test_removed_record_is_not_a_verified_fix_even_with_complete_scans():
    before, after = scan("before", 16), scan()
    after["findings"] = []
    result = build_impact_brief(after, before=before)
    assert result["comparison"]["not_observed"] == ["f1"]
    assert result["comparison"]["verified_fixes"] is None
    assert "not proof" in result["comparison"]["claim_boundary"]
    assert result["comparison"]["scope_status"] == "matching_recorded_scope"
    receipt = result["comparison"]["receipts"][0]
    assert receipt["before_pointer"] == "/findings/0"
    assert receipt["before"]["id"] == "f1"


def test_partial_or_missing_coverage_remains_visible():
    doc = scan()
    doc["scan_run"] = {"outcome": "partial", "scopes": [], "issues": [{"message": "Denied", "affects_coverage": True}]}
    result = build_impact_brief(doc, before=scan("before", 16))
    assert result["comparison"]["scope_status"] == "unverified"
    assert result["current"]["coverage"]["outcome"] == "partial"
    assert "Denied" in json.dumps(result)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d["findings"].append({**finding(), "severity": "critical"}),
        lambda d: d["findings"][0].update(id=""),
        lambda d: d["findings"][0].update(occurrence_id="different"),
        lambda d: d.update(findings=None),
        lambda d: d.update(document_type="unknown"),
        lambda d: d.update(generated_at="not-a-date"),
        lambda d: d["exposure_paths"].update(paths=[{"id": "p"}, {"id": "p", "source": "different"}]),
    ],
)
def test_ambiguous_inputs_fail_before_aggregation(mutation):
    doc = scan()
    mutation(doc)
    with pytest.raises(ValueError):
        build_impact_brief(doc)


@pytest.mark.parametrize("field,value", [("tenant_id", "another"), ("canonical_id_schema_version", "2"), ("scan_id", "before")])
def test_incompatible_comparisons_are_rejected(field, value):
    after = scan()
    after[field] = value
    with pytest.raises(ValueError):
        build_impact_brief(after, before=scan("before", 16))


def test_missing_ids_are_unknown_and_labels_never_become_identity():
    doc = scan()
    doc["findings"][0]["asset"] = {"name": "same-name"}
    doc["findings"][0]["evidence"] = {"agent_server_links": [{"agent": "same-name"}]}
    result = build_impact_brief(doc)["current"]
    assert result["counts"]["agent_ids"] == result["counts"]["asset_ids"] == 0
    assert result["counts"]["occurrences_without_asset_id"] == 1
    assert result["counts"]["occurrences_without_agent_id"] == 1


def test_limit_bounds_details_without_changing_totals_or_losing_source_receipt():
    doc = scan()
    doc["findings"] = [finding(str(n), str(n)) for n in range(6)]
    doc["findings"][5]["severity"] = "critical"
    result = build_impact_brief(doc, limit=2)
    assert result["current"]["counts"]["finding_occurrences"] == 6
    assert len(result["current"]["priorities"]) == 2
    assert result["current"]["priorities"][0]["id"] == "5"
    assert result["current"]["omitted_occurrences"] == 4
    assert len(result["current"]["source_sha256"]) == 64


def test_html_is_scriptless_escaped_redacted_and_has_expandable_receipts():
    doc = scan()
    doc["findings"][0]["title"] = '<script>alert("oops")</script>'
    secret = "sk-" + "examplecredentialvalue" * 3
    doc["findings"][0]["evidence"]["api_key"] = secret
    result = build_impact_brief(doc)
    html = render_impact_brief(result)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert secret not in html and secret not in json.dumps(result)
    assert "<details" in html and "/findings/0" in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "https://" not in html
    assert "Potential consequence" in html and "not established" in html


def test_cli_generates_html_and_refuses_to_overwrite(tmp_path):
    from agent_bom.cli import main

    path, out = tmp_path / "scan.json", tmp_path / "brief.html"
    path.write_text(json.dumps(scan()))
    runner = CliRunner()
    args = ["report", "impact", str(path), "-o", str(out)]
    result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert out.read_text().startswith("<!doctype html>")
    original = out.read_bytes()
    assert runner.invoke(main, args).exit_code != 0
    assert out.read_bytes() == original


def test_cli_rejects_duplicate_json_keys_without_creating_artifact(tmp_path):
    from agent_bom.cli import main

    path, out = tmp_path / "bad.json", tmp_path / "brief.json"
    path.write_text('{"findings": [], "findings": []}')
    result = CliRunner().invoke(main, ["report", "impact", str(path), "--format", "json", "-o", str(out)])
    assert result.exit_code != 0 and not out.exists()


def test_changed_records_retain_both_receipts_and_exact_source_positions():
    before, after = scan("before", 16), scan()
    after["findings"][0]["severity"] = "critical"
    result = build_impact_brief(after, before=before)
    assert result["comparison"]["counts"]["changed"] == 1
    row = result["comparison"]["receipts"][0]
    assert row["before"]["severity"] == "high" and row["after"]["severity"] == "critical"
    assert row["before_pointer"] == row["after_pointer"] == "/findings/0"


def test_paths_retain_direction_and_evidence_without_becoming_findings():
    doc = scan()
    path = {"id": "p1", "finding_id": "f1", "source": "a", "target": "b", "evidence": {"basis": "configured"}}
    doc["exposure_paths"]["paths"] = [path]
    result = build_impact_brief(doc)["current"]
    assert result["paths"][0]["receipt"] == path
    assert result["paths"][0]["receipt_pointer"] == "/exposure_paths/paths/0"
    assert result["counts"]["finding_occurrences"] == 1


def test_large_receipt_is_explicitly_omitted_but_still_counted():
    doc = scan()
    doc["findings"][0]["evidence"]["description"] = "long source evidence " * 4000
    result = build_impact_brief(doc)["current"]
    assert result["counts"]["finding_occurrences"] == 1
    assert result["priorities"][0]["receipt"]["detail_omitted"] is True


@pytest.mark.parametrize("limit", [0, 51, True, 1.5])
def test_detail_budget_is_strict(limit):
    with pytest.raises(ValueError):
        build_impact_brief(scan(), limit=limit)


def test_conflicting_asset_ids_and_changed_scope_do_not_inflate_confidence():
    doc = scan()
    doc["findings"].append(finding("f2"))
    doc["findings"][1]["asset"]["name"] = "different owner"
    with pytest.raises(ValueError):
        build_impact_brief(doc)
    doc = scan()
    doc["scan_run"]["scopes"][0]["name"] = "different scope"
    assert build_impact_brief(doc, before=scan("before", 16))["comparison"]["scope_status"] == "unverified"


def test_unknown_path_collection_and_unknown_identity_scheme_are_not_complete():
    doc = scan()
    del doc["exposure_paths"]
    assert build_impact_brief(doc)["current"]["counts"]["recorded_paths"] is None
    before = scan("before", 16)
    del doc["canonical_id_schema_version"]
    del before["canonical_id_schema_version"]
    with pytest.raises(ValueError):
        build_impact_brief(doc, before=before)


@pytest.mark.parametrize("field,value", [("warnings", ["collection incomplete"]), ("scan_sources", [])])
def test_scope_matching_preserves_top_level_warnings_and_missing_sources(field, value):
    doc = scan()
    doc[field] = value
    result = build_impact_brief(doc, before=scan("before", 16))
    assert result["comparison"]["scope_status"] == "unverified"


def test_redacted_tenant_labels_cannot_collapse_to_one_comparison_scope():
    before, after = scan("before", 16), scan()
    before["tenant_id"] = "tenant:REDACTED:one"
    after["tenant_id"] = "tenant:REDACTED:two"
    with pytest.raises(ValueError):
        build_impact_brief(after, before=before)
