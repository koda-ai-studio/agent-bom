"""Exclusive work queues derived from finding evidence, separate from posture lenses."""

from collections.abc import Mapping
from typing import Any, Literal

FindingLane = Literal["vulnerabilities", "cloud", "iac", "secrets", "identity", "data", "other"]
FINDING_LANES = ("vulnerabilities", "cloud", "iac", "secrets", "identity", "data", "other")


def finding_lane(row: Mapping[str, Any]) -> str:
    """Recompute from canonical evidence; a supplied lane is never authoritative."""
    from agent_bom.finding_scope import _is_iac_misconfig, finding_class_for_row

    kind = finding_class_for_row(dict(row))
    if kind in ("vulnerability", "secret", "identity", "pii"):
        return {"vulnerability": "vulnerabilities", "secret": "secrets", "identity": "identity", "pii": "data"}[kind]
    evidence = row.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    asset = row.get("asset")
    asset = asset if isinstance(asset, Mapping) else {}
    if kind == "misconfiguration":
        from agent_bom.finding import FindingType

        if asset.get("asset_type") == "iac_resource" or _is_iac_misconfig(None, FindingType.CIS_FAIL, dict(evidence)):
            return "iac"
        if str(row.get("finding_type") or "").strip().upper() in {
            "CIS_FAIL",
            "CIS_ERROR",
            "CLOUD_BEST_PRACTICE_FAIL",
            "CLOUD_BEST_PRACTICE_ERROR",
        }:
            return "cloud"
    return "other"


def lane_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(FINDING_LANES, 0)
    for row in rows:
        counts[finding_lane(row)] += 1
    return counts


def lane_response_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    from agent_bom.security import sanitize_text

    evidence = row.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    source = row.get("severity_source") or evidence.get("severity_source")
    return {"lane": finding_lane(row), **({"severity_source": sanitize_text(source, max_len=64)} if isinstance(source, str) else {})}


def model_lane_fields(finding: Any) -> dict[str, Any]:
    return {
        "severity_source": finding.severity_source or finding.evidence.get("severity_source"),
        "lane": finding_lane(
            {
                "finding_type": finding.finding_type.value,
                "source": finding.source.value,
                "asset": {"asset_type": finding.asset.asset_type},
                "evidence": finding.evidence,
            }
        ),
    }
