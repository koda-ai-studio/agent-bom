"""Public report redaction must not merge files or break finding references."""

import copy
import json

import pytest

from agent_bom.evidence.finding_node_ids import iac_misconfig_node_id
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.output.json_fmt import redact_json_payload


@pytest.mark.parametrize(
    "paths",
    [
        [
            "tests/fixtures/iac_golden/cloudformation/harvested_051347c8735e59e8.json",
            "tests/fixtures/iac_golden/cloudformation/harvested_6eb5830bb2016890.json",
        ],
        ["/private/one/main.tf", "/private/two/main.tf"],
        ["config/" + "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789" + "/main.tf", "/private/two/main.tf"],
    ],
)
def test_redacted_iac_graph_keeps_distinct_files_and_resolvable_references(paths):
    report = {"iac_findings": {"findings": []}, "findings": []}
    for index, path in enumerate(paths):
        hit = {
            "rule_id": "CFN-014",
            "category": "cloudformation",
            "file_path": path,
            "line_number": 4,
            "title": "Public resource",
            "severity": "high",
        }
        report["iac_findings"]["findings"].append(hit)
        report["findings"].append(
            {
                "id": f"finding-{index}",
                "finding_type": "CIS_FAIL",
                "source": "IAC_SCAN",
                "severity": "high",
                "node_id": f"iac_target:cloudformation:{path}",
                "finding_node_id": iac_misconfig_node_id("CFN-014", path, 4),
                "evidence": {"iac": True, **hit},
            }
        )
    original = copy.deepcopy(report)
    before = build_unified_graph_from_report(copy.deepcopy(report))
    public = redact_json_payload(report)
    after = build_unified_graph_from_report(copy.deepcopy(public))
    # Private directory hierarchy can disappear; the findings and file targets cannot.
    for prefix in ("misconfig:iac:", "iac_target:"):
        assert sum(key.startswith(prefix) for key in after.nodes) == sum(key.startswith(prefix) for key in before.nodes) == 2
    for finding in public["findings"]:
        assert finding["node_id"] in after.nodes
        assert finding["finding_node_id"] in after.nodes
        assert after.has_edge(finding["finding_node_id"], finding["node_id"])
    assert len({hit["file_path"] for hit in public["iac_findings"]["findings"]}) == 2
    assert all(path not in json.dumps(public) for path in paths)
    assert report == original
    assert redact_json_payload(public) == public
    reversed_report = copy.deepcopy(report)
    reversed_report["iac_findings"]["findings"].reverse()
    assert redact_json_payload(reversed_report)["findings"] == public["findings"]


def test_real_finding_serializer_links_survive_redaction():
    from agent_bom.finding import iac_finding_to_finding
    from agent_bom.graph.asset_entity import link_findings_to_graph_nodes
    from agent_bom.models import AIBOMReport
    from agent_bom.output.json_fmt import to_json, to_redacted_json

    hits = [
        {"rule_id": rule, "category": "terraform", "file_path": path, "line_number": 4, "title": "Public resource", "severity": "high"}
        for rule in ("TF-001", "TF-002")
        for path in ("/private/one/main.tf", "/private/two/main.tf")
    ]
    findings = [iac_finding_to_finding(hit) for hit in hits]
    report = AIBOMReport(agents=[], findings=findings, iac_findings_data={"findings": hits})
    graph = build_unified_graph_from_report(to_json(report))
    assert link_findings_to_graph_nodes(findings, graph) == 4
    public = to_redacted_json(report)
    rebuilt = build_unified_graph_from_report(public)
    for row in public["findings"]:
        assert row["node_id"] in rebuilt.nodes
        assert row["finding_node_id"] in rebuilt.nodes
    assert len({row["node_id"] for row in public["findings"]}) == 2
    assert len({row["finding_node_id"] for row in public["findings"]}) == 4
    assert "/private/" not in json.dumps(public)


def test_safe_paths_legacy_placeholders_and_secret_fields_keep_their_policy():
    for path in ("infra/main.tf", "***REDACTED***", "<path:main.tf>"):
        report = {"iac_findings": {"findings": [{"file_path": path}]}}
        assert redact_json_payload(report) == report
    report = {"iac_findings": {"findings": [{"file_path": "/private/main.tf"}]}, "api_key": "/private/main.tf"}
    report["cycle"] = report
    public = redact_json_payload(report)
    assert public["api_key"] == "***REDACTED***"
    assert "/private/" not in json.dumps(public)
