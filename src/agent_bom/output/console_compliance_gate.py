"""Decide whether the compact GOVERN block has anything honest to say.

Framework mapping is opt-in (``--compliance``) or a by-product of a benchmark
run. On a plain local scan neither happened, so a block of "action required"
counts and "not evaluated" frameworks reads as a verdict the scan never made.
"""

from __future__ import annotations

import agent_bom.output as _out
from agent_bom.domain.finding_types import FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output.brand_tokens import lane_title
from agent_bom.output.compact import print_compact_compliance_status

_FRAMEWORK_HINT = "run with --compliance"


def has_compliance_evidence(report: AIBOMReport) -> bool:
    """True when a benchmark ran or a non-IaC control finding is in the stream."""
    benchmarks = (
        report.cis_benchmark_data,
        report.azure_cis_benchmark_data,
        report.gcp_cis_benchmark_data,
        report.snowflake_cis_benchmark_data,
        report.databricks_cis_benchmark_data,
    )
    if any(benchmarks):
        return True
    for finding in getattr(report, "findings", None) or []:
        if finding.finding_type in {FindingType.CIS_FAIL, FindingType.CIS_ERROR} and not (finding.evidence or {}).get("iac"):
            return True
    return False


def print_compact_compliance_section(report: AIBOMReport, *, compliance_enabled: bool) -> None:
    """Render the GOVERN block, or one line naming the flag that would populate it."""
    if compliance_enabled or has_compliance_evidence(report):
        print_compact_compliance_status(report)
        return
    _out.console.print(f"  {lane_title('govern', 'Compliance evidence')} [dim]not evaluated · {_FRAMEWORK_HINT}[/dim]\n")


__all__ = ["has_compliance_evidence", "print_compact_compliance_section"]
