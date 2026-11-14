"""A pushed report's string warnings must not re-grade notes the CLI already classified."""

import json

from agent_bom.api.posture_recompute import compute_posture_scorecard_from_result
from agent_bom.api.push_models import normalize_push_coverage
from agent_bom.evidence.scan_run import result_vulnerability_coverage_incomplete, vulnerability_coverage_incomplete
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import to_json
from agent_bom.posture import compute_posture_scorecard

SCOPE = "v1:" + "a" * 64
MAVEN_DETAIL = (
    "Maven inventory for ./pom.xml lists 1 direct (declared) dependencies; transitive dependencies are resolved "
    "by Maven at build time and were not inventoried, so vulnerabilities in them are not reported."
)


def _maven_note_report() -> AIBOMReport:
    report = AIBOMReport(
        agents=[
            Agent(
                name="project:pom",
                agent_type=AgentType.CUSTOM,
                config_path="pom.xml",
                mcp_servers=[
                    MCPServer(
                        name="pom",
                        registry_verified=True,
                        packages=[Package(name="org.apache.logging.log4j:log4j-core", version="2.14.1", ecosystem="maven")],
                    )
                ],
            )
        ]
    )
    report.coverage_warnings = [
        {
            "ecosystem": "maven",
            "release": "maven-note:./pom.xml",
            "reason": "maven_transitive_unresolved",
            "detail": MAVEN_DETAIL,
            "package_count": 0,
            "advisory_rows": 0,
            "kind": "scan_note",
        }
    ]
    return report


def test_pushed_maven_note_scan_keeps_its_cli_grade():
    report = _maven_note_report()
    cli_score = compute_posture_scorecard(report)
    assert not vulnerability_coverage_incomplete(report)
    payload = json.loads(json.dumps(to_json(report)))
    assert payload["warnings"], "the CLI report repeats the note as a legacy string warning"

    normalized = normalize_push_coverage(payload, source_id="runner", target_scope=SCOPE)

    assert not result_vulnerability_coverage_incomplete(normalized)
    assert all(w.get("kind") != "legacy_scan_warning" for w in normalized["coverage_warnings"])
    assert all(i["code"] != "legacy_scan_warning" for i in normalized["scan_run"]["issues"])
    assert normalized["scan_run"]["outcome"] == "complete"
    pushed = compute_posture_scorecard_from_result(normalized)
    assert pushed.grade != "N/A"
    assert pushed.grade == cli_score.grade


def test_pushed_note_matching_only_detail_is_still_deduplicated():
    payload = json.loads(json.dumps(to_json(_maven_note_report())))
    payload["warnings"] = [MAVEN_DETAIL]
    payload.pop("scan_run", None)

    normalized = normalize_push_coverage(payload, source_id="runner", target_scope=SCOPE)

    assert not result_vulnerability_coverage_incomplete(normalized)


def test_unstructured_legacy_warning_still_fails_closed():
    payload = json.loads(json.dumps(to_json(_maven_note_report())))
    payload["warnings"] = [*payload["warnings"], "OSV query failed for 12 packages; vulnerability data incomplete"]

    normalized = normalize_push_coverage(payload, source_id="runner", target_scope=SCOPE)

    assert result_vulnerability_coverage_incomplete(normalized)
    assert any(w.get("kind") == "legacy_scan_warning" for w in normalized["coverage_warnings"])
    assert compute_posture_scorecard_from_result(normalized).grade == "N/A"
