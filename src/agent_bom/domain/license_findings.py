"""License-policy violations as unified findings.

The license check serializes its verdicts into ``license_report``; these rows
put each violation into the finding stream so severity gates, exports, the
findings API and the graph see it like any other finding.
"""

from __future__ import annotations

from typing import Any

from agent_bom.compliance_hub import apply_hub_classification
from agent_bom.finding import Asset, Finding, FindingSource, FindingType


def license_report_to_findings(license_report: Any) -> list[Finding]:
    if not isinstance(license_report, dict):
        return []
    findings: list[Finding] = []
    for item in license_report.get("findings") or []:
        if not isinstance(item, dict) or not item.get("package_name"):
            continue
        name, version = str(item["package_name"]), str(item.get("package_version") or "")
        ecosystem = str(item.get("ecosystem") or "")
        license_id = str(item.get("license_id") or item.get("license_expression") or "unknown")
        category = str(item.get("category") or "policy")
        agents = [str(agent) for agent in item.get("agents") or []]
        from_sbom = bool(agents) and all(agent.startswith("sbom:") for agent in agents)
        purl = f"pkg:{ecosystem}/{name}@{version}" if ecosystem and version else name
        findings.append(
            apply_hub_classification(
                Finding(
                    finding_type=FindingType.LICENSE,
                    source=FindingSource.SBOM if from_sbom else FindingSource.MCP_SCAN,
                    asset=Asset(name=name, asset_type="package", identifier=purl),
                    severity=str(item.get("risk_level") or "medium").lower(),
                    title=f"{license_id} license ({category.replace('_', ' ')}) on {name}" + (f"@{version}" if version else ""),
                    description=str(item.get("reason") or f"License {license_id} violates the license policy"),
                    remediation_guidance="Replace the package with one under an allowed license, or record a policy exception.",
                    evidence={
                        "rule_id": f"license:{category}",
                        "license_id": license_id,
                        "license_expression": item.get("license_expression"),
                        "category": category,
                        "package_name": name,
                        "package_version": version,
                        "ecosystem": ecosystem,
                    },
                    affected_agents=agents,
                )
            )
        )
    return findings


def replace_license_findings(report: Any) -> int:
    """Replace LICENSE rows on ``report.findings`` from its serialized license report."""
    retained = [finding for finding in report.findings if finding.finding_type is not FindingType.LICENSE]
    added = license_report_to_findings(report.license_report)
    report.findings = retained + added
    return len(added)
