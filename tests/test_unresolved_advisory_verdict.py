"""Unverified advisory candidates must remain visible without a clean verdict."""

import csv
import io

from agent_bom.evidence.scan_run import effective_scan_run
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import to_csv, to_markdown
from agent_bom.output.cis_posture import finding_free_posture
from agent_bom.posture import compute_posture_scorecard


def _report():
    package = Package(name="pillow", version="9.5.0", ecosystem="pypi", floating_reference=True, resolved_from_registry=True)
    package.possibly_affected = [
        {
            "id": "CVE-2023-4863",
            "verdict": "possibly_affected",
            "reason": "registry_selected_version",
            "detail": "Installed version unknown; lock the dependency to confirm",
            "severity": "critical",
        }
    ]
    return AIBOMReport(
        agents=[
            Agent(
                name="fixture",
                agent_type=AgentType.CUSTOM,
                config_path="fixture.json",
                mcp_servers=[
                    MCPServer(name="packages", command="pip", packages=[package]),
                ],
            )
        ],
        blast_radii=[],
    )


def test_unresolved_advisories_are_partial_not_clean_or_graded():
    report = _report()
    assert effective_scan_run(report).outcome.value == "partial"
    assert finding_free_posture(report)[1] != "CLEAN"
    assert compute_posture_scorecard(report).grade == "N/A"
    assert report.total_vulnerabilities == 0


def test_markdown_and_csv_preserve_review_candidates():
    report = _report()
    markdown = to_markdown(report)
    assert "CVE-2023-4863" in markdown and "pillow" in markdown
    assert "possibly affected" in markdown.lower()
    rows = list(csv.DictReader(io.StringIO(to_csv(report).lstrip("\ufeff"))))
    row = next(r for r in rows if r["cve_id"] == "CVE-2023-4863")
    assert row["package"] == "pillow"
    assert row["finding_type"] == "possibly_affected"
