"""Overlay the tenant's confirmed operator-advisory matches on a report before its graph is built.

The graph then carries a vulnerability node and a ``vulnerable_to`` edge from
the package, so blast radius and attack paths include day-zero advisories the
feeds have not published yet. Kept apart from the affected-assets read so the
graph persistence path imports nothing but the advisory store and matcher.
"""

from __future__ import annotations

import copy
from typing import Any

from agent_bom.db.operator_advisories import distro_verdicts
from agent_bom.scanners.operator_advisory import (
    OPERATOR_ADVISORY_PROVENANCE,
    OperatorAdvisory,
    match_advisories_against_reports,
    occurrence_id,
)


def _advisory_vulnerability(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": finding["advisory_id"],
        "aliases": finding["aliases"],
        "summary": finding["summary"],
        "severity": finding["severity"],
        "fixed_version": finding["fixed_version"],
        "provenance": finding["provenance"],
        "finding_id": finding["id"],
        "source": finding["provenance"],
    }


def with_advisory_vulnerabilities(report: dict[str, Any], declared_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The report with the tenant's confirmed operator-advisory matches on their packages, for the graph build only.

    The stored report is never changed; a report with no match is returned as is.
    Possibly-affected distro packages are not vulnerabilities and get no node.
    """
    declared = [OperatorAdvisory.model_validate({k: v for k, v in row.items() if k != "updated_at"}) for row in declared_rows]
    if not declared:
        return report
    with distro_verdicts() as verdict:
        findings = match_advisories_against_reports(declared, [report], distro_verdict=verdict).findings
    if not findings:
        return report
    by_occurrence = {finding["id"]: finding for finding in findings}
    overlaid = copy.deepcopy(report)
    for agent in overlaid.get("agents") or []:
        for server in agent.get("mcp_servers") or []:
            asset = {"agent": str(agent.get("name") or ""), "server": str(server.get("name") or "")}
            for package in server.get("packages") or []:
                for advisory in declared:
                    finding = by_occurrence.get(occurrence_id(advisory.id, package, asset, OPERATOR_ADVISORY_PROVENANCE))
                    if finding is not None:
                        package.setdefault("vulnerabilities", []).append(_advisory_vulnerability(finding))
    return overlaid
