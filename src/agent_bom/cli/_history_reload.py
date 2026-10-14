"""What a compliance narrative needs back from a saved JSON report.

The ``blast_radius`` block of a saved report omits fields only the unified
``findings`` stream carries: owner and SLA, and — on reports saved before
package rows carried them — ``cwe_ids``. Both joins key on
``(advisory, package@version)``. The run's coverage receipts are restored too,
so a partial vulnerability lane keeps its detective controls unpassed on reload.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.evidence.scan_run import serialized_coverage_view

AdvisoryKey = tuple[str, str]


def advisory_key(row: Mapping[str, Any]) -> AdvisoryKey:
    """Return the ``(advisory, package@version)`` join key of one finding row."""
    raw_evidence = row.get("evidence")
    evidence: Mapping[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
    return (
        str(row.get("cve_id") or row.get("vulnerability_id") or ""),
        f"{evidence.get('package_name') or ''}@{evidence.get('package_version') or ''}",
    )


def finding_cwe_index(findings: Iterable[Mapping[str, Any]]) -> dict[AdvisoryKey, list[str]]:
    """Index each advisory's ``cwe_ids`` from the finding stream; the first row wins.

    The CWE is the check that evidences a NIST catalog control, so it must
    survive the reload even when the package row did not carry it.
    """
    index: dict[AdvisoryKey, list[str]] = {}
    for row in findings:
        if isinstance(row.get("cwe_ids"), list):
            index.setdefault(advisory_key(row), [str(cwe) for cwe in row["cwe_ids"]])
    return index


def blast_radius_cwe_ids(br: Mapping[str, Any], key: AdvisoryKey, finding_cwes: Mapping[AdvisoryKey, list[str]]) -> list[str]:
    """The package row's own ``cwe_ids``, else the finding stream's for the same advisory."""
    raw_cwes = br.get("cwe_ids")
    return [str(cwe) for cwe in raw_cwes] if isinstance(raw_cwes, list) else finding_cwes.get(key, [])


def finding_ownership_index(findings: Iterable[Mapping[str, Any]]) -> dict[AdvisoryKey, dict[str, object]]:
    """Index each advisory's owner (first set) and earliest SLA due date."""
    ownership: dict[AdvisoryKey, dict[str, object]] = {}
    for row in findings:
        if str(row.get("finding_type") or "CVE") != "CVE":
            continue
        slot = ownership.setdefault(advisory_key(row), {"owner": None, "sla_due_at": None})
        slot["owner"] = slot["owner"] or row.get("owner")
        due = row.get("sla_due_at")
        if isinstance(due, str) and due and (not slot["sla_due_at"] or due < str(slot["sla_due_at"])):
            slot["sla_due_at"] = due
    return ownership


def saved_coverage_receipts(data: dict[str, Any]) -> dict[str, Any]:
    """The report attributes :func:`agent_bom.evidence.scan_run.vulnerability_coverage_incomplete` reads."""
    coverage = serialized_coverage_view(data)
    return {
        "scan_run": coverage.scan_run,
        "scan_performance_data": coverage.scan_performance_data,
        "coverage_warnings": coverage.coverage_warnings,
    }
