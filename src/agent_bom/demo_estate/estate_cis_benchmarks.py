"""The demo scan's CIS benchmark blobs, derived from its own CIS findings.

The graph projects the estate's CIS findings (:mod:`enterprise_findings`) as one
failure node per check. The stored benchmark blobs that ``/v1/cis/checks``, the
scorecard and exports read are built here from the same serialized rows, so the
two cannot disagree about a control's numbering, status or resources.

Only what the estate records is reported: a check fails when a resource failed
it, and is ``error`` when it could only be attempted. The estate records no
passing results, so no check is reported as passing.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agent_bom.evidence.finding_node_ids import _BENCHMARK_SECTIONS

# Name and version the shipped scanner reports for each cloud
# (``agent_bom.cloud.*_cis``), so a demo blob reads like a live one.
_BENCHMARKS: dict[str, tuple[str, str]] = {
    "aws": ("CIS AWS Foundations", "3.0"),
    "azure": ("CIS Microsoft Azure Foundations", "3.0"),
    "gcp": ("CIS Google Cloud Platform Foundation", "3.0"),
    "snowflake": ("CIS Snowflake Foundations", "1.0"),
}
_CIS_TYPES = frozenset({"CIS_FAIL", "CIS_ERROR"})


@dataclass
class _Check:
    check_id: str
    title: str
    cis_section: str
    severity: str = "unknown"
    remediation: dict[str, Any] = field(default_factory=dict)
    failing: set[str] = field(default_factory=set)
    unevaluated: set[str] = field(default_factory=set)


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _evidence(row: dict[str, Any]) -> dict[str, Any]:
    return _as_dict(row.get("evidence"))


def _remediation(row: dict[str, Any]) -> dict[str, Any]:
    remediation = _as_dict(row.get("remediation"))
    fix = _as_dict(remediation.get("fix"))
    return {
        "fix_cli": fix.get("cli"),
        "fix_console": str(fix.get("console") or ""),
        "docs": fix.get("docs"),
        "effort": str(remediation.get("effort") or "manual"),
        "priority": int(remediation.get("priority") or 0),
        "guardrails": [str(item) for item in remediation.get("guardrails") or []],
        "requires_human_review": True,
    }


def _cis_rows(rows: Iterable[Any]) -> Iterable[tuple[str, dict[str, Any], dict[str, Any]]]:
    for row in rows:
        if not isinstance(row, dict) or row.get("source") != "CLOUD_CIS" or row.get("finding_type") not in _CIS_TYPES:
            continue
        evidence = _evidence(row)
        provider = str(evidence.get("provider") or row.get("provider") or "").lower()
        if provider in _BENCHMARKS and evidence.get("check_id") and evidence.get("resource_id"):
            yield provider, row, evidence


def _collect(rows: Iterable[Any]) -> dict[str, dict[str, _Check]]:
    by_cloud: dict[str, dict[str, _Check]] = {}
    for provider, row, evidence in _cis_rows(rows):
        check_id = str(evidence["check_id"])
        check = by_cloud.setdefault(provider, {}).setdefault(
            check_id,
            _Check(
                check_id=check_id, title=str(evidence.get("control_title") or check_id), cis_section=str(evidence.get("cis_section") or "")
            ),
        )
        resource = str(evidence["resource_id"])
        if str(evidence.get("status") or "").upper() == "ERROR":
            check.unevaluated.add(resource)
            continue
        check.failing.add(resource)
        check.severity = str(row.get("severity") or "unknown").lower()
        check.remediation = check.remediation or _remediation(row)
    return by_cloud


def _check_payload(check: _Check) -> dict[str, Any]:
    failing = sorted(check.failing)
    unevaluated = sorted(check.unevaluated - check.failing)
    status = "fail" if failing else "error"
    evidence = f"{len(failing)} resource(s) fail this control." if failing else ""
    if unevaluated:
        evidence = f"{evidence} {len(unevaluated)} resource(s) could not be evaluated.".strip()
    return {
        "check_id": check.check_id,
        "title": check.title,
        "status": status,
        "severity": check.severity if failing else "unknown",
        "cis_section": check.cis_section,
        "evidence": evidence,
        "resource_ids": failing,
        "unevaluated_resource_ids": unevaluated,
        "remediation": check.remediation,
    }


def _benchmark(cloud: str, checks: dict[str, _Check]) -> dict[str, Any]:
    name, version = _BENCHMARKS[cloud]
    payloads = [_check_payload(check) for _, check in sorted(checks.items())]
    failed = sum(1 for check in payloads if check["status"] == "fail")
    errored = sum(1 for check in payloads if check["status"] == "error")
    return {
        "benchmark": name,
        "benchmark_version": version,
        "provider": cloud,
        "passed": 0,
        "failed": failed,
        "errored": errored,
        "total": len(payloads),
        "pass_rate": 0.0,
        "checks": payloads,
    }


def estate_cis_benchmarks(rows: Iterable[Any]) -> dict[str, dict[str, Any]]:
    """Benchmark blobs keyed by report section, from serialized CIS finding rows."""
    return {_BENCHMARK_SECTIONS[cloud]: _benchmark(cloud, checks) for cloud, checks in sorted(_collect(rows).items())}


__all__ = ["estate_cis_benchmarks"]
