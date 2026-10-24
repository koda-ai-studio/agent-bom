"""Recorded scan history for the showcase scope.

The demo's posture trend is a series of scans of one scope, each persisted as a
demo job and trended through the same recording path a live scan uses, so the
history chart, its comparisons and the posture headline are one derivation.

Every stage is derived deterministically from the curated current report:

* a posture finding *arrives* at one stage and stays; its ``first_seen`` is
  that stage's scan time, so no finding claims an age older than the scans
  that saw it;
* a *retired* finding is the same check failing on another inventoried
  resource of the same kind; it is open in the early stages, may be accepted
  by an operator VEX statement for one stage, and is no longer detected from
  its fix stage on. It never appears in the current scan.

Vulnerability rows stay constant: their package occurrences are shared with
the hand-built graph paths the other demo surfaces assert on.
"""

from __future__ import annotations

import copy
import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from agent_bom.demo_estate.estate_cis_benchmarks import estate_cis_benchmarks, recorded_cis_passes
from agent_bom.demo_estate.showcase_constants import (
    SHOWCASE_BASELINE_CREATED_AT,
    SHOWCASE_BASELINE_SCAN_ID,
    SHOWCASE_CURRENT_CREATED_AT,
    SHOWCASE_SCAN_ID,
)
from agent_bom.output.json_fmt import _build_finding_summary

HISTORY_SCOPE_ID = "demo-estate:showcase-findings:v1"
_EARLY_OFFSETS_DAYS = (27, 22, 17, 12)
# Share of posture findings first detected at each stage, earliest first.
_ARRIVAL_SHARES = (0.67, 0.06, 0.04, 0.01, 0.08, 0.14)
_RETIRED_SHARE = 0.14
# Share of retired findings fixed at each later stage; the third is a remediation push.
_FIX_SHARES = (0.12, 0.14, 0.52, 0.1, 0.12)
_RETIRED_SEVERITIES = frozenset({"critical", "high", "medium"})
_CIS_SECTIONS = frozenset({"cis_benchmark", "azure_cis_benchmark", "gcp_cis_benchmark", "snowflake_cis_benchmark"})
_NAMESPACE = uuid.UUID("7f1d3c56-2f8e-4b0a-9a52-3c3c6b1d8e01")


@dataclass(frozen=True)
class HistoryStage:
    scan_id: str
    timestamp: str
    job_id: str


def history_stages() -> tuple[HistoryStage, ...]:
    """Every recorded scan of the showcase scope, oldest first; the last is the current scan."""
    current = datetime.fromisoformat(SHOWCASE_CURRENT_CREATED_AT)
    early = tuple(
        HistoryStage(
            scan_id=f"showcase-history-{index + 1}",
            timestamp=(current - timedelta(days=days)).isoformat(),
            job_id=str(uuid.uuid5(_NAMESPACE, f"stage-job:{index + 1}")),
        )
        for index, days in enumerate(_EARLY_OFFSETS_DAYS)
    )
    baseline = HistoryStage(SHOWCASE_BASELINE_SCAN_ID, SHOWCASE_BASELINE_CREATED_AT, str(uuid.uuid5(_NAMESPACE, "stage-job:baseline")))
    return (*early, baseline, HistoryStage(SHOWCASE_SCAN_ID, SHOWCASE_CURRENT_CREATED_AT, ""))


def _fraction(*parts: str) -> float:
    digest = hashlib.sha256("\x1f".join(parts).encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def _is_posture_row(row: Any) -> bool:
    return isinstance(row, dict) and bool(row.get("id")) and not (row.get("vulnerability_id") or row.get("cve_id"))


def _bucket(value: float, shares: tuple[float, ...]) -> int:
    cumulative = 0.0
    for index, share in enumerate(shares):
        cumulative += share
        if value < cumulative:
            return index
    return len(shares) - 1


def _arrival_stage(row: dict[str, Any]) -> int:
    return _bucket(_fraction("arrival", str(row["id"])), _ARRIVAL_SHARES)


def _evidence(row: dict[str, Any]) -> dict[str, Any]:
    evidence = row.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


@dataclass(frozen=True)
class _Retired:
    row: dict[str, Any]
    fixed_at: int
    suppressed_from: int | None


def _retired_rows(rows: list[dict[str, Any]], stage_count: int) -> list[_Retired]:
    """The same check failing on another same-kind resource, fixed before the current scan."""
    kinds: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    current = set()
    for row in rows:
        evidence = _evidence(row)
        if evidence.get("resource_id") and evidence.get("check_id"):
            current.add((str(evidence["check_id"]), str(evidence["resource_id"])))
            kind = (str(row.get("finding_type") or ""), str(row.get("provider") or ""), str(evidence.get("resource_type") or ""))
            kinds.setdefault(kind, []).append(row)
    retired: list[_Retired] = []
    for kind, members in sorted(kinds.items()):
        members = sorted(members, key=lambda row: str(row["id"]))
        for position, source in enumerate(members):
            if source.get("severity") not in _RETIRED_SEVERITIES or _fraction("retired", str(source["id"])) >= _RETIRED_SHARE:
                continue
            check = str(_evidence(source)["check_id"])
            donor = next(
                (
                    candidate
                    for candidate in members[position + 1 :] + members[:position]
                    if (check, str(_evidence(candidate)["resource_id"])) not in current
                ),
                None,
            )
            if donor is None:
                continue
            donor_evidence = _evidence(donor)
            current.add((check, str(donor_evidence["resource_id"])))
            clone = copy.deepcopy(source)
            finding_id = str(uuid.uuid5(_NAMESPACE, f"retired:{source['id']}:{donor_evidence['resource_id']}"))
            clone.update(
                id=finding_id,
                finding_id=finding_id,
                canonical_id=finding_id,
                node_id=donor.get("node_id"),
                entity_type=donor.get("entity_type"),
                asset=copy.deepcopy(donor.get("asset")),
            )
            clone["evidence"] = {
                **_evidence(source),
                **{
                    key: donor_evidence[key]
                    for key in ("resource_id", "resource_name", "resource_type", "principal_id")
                    if key in donor_evidence
                },
            }
            if isinstance(clone.get("asset"), dict) and donor_evidence.get("resource_name"):
                clone["asset"]["name"] = donor_evidence["resource_name"]
            fixed_at = 1 + _bucket(_fraction("fixed", finding_id), _FIX_SHARES[: stage_count - 1])
            suppressed = fixed_at >= 2 and _fraction("suppressed", finding_id) < 0.3
            retired.append(_Retired(clone, fixed_at, fixed_at - 1 if suppressed else None))
    return retired


def _operator_vex(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "vex_status": "not_affected",
        "vex_justification": "inline_mitigations_already_exist",
        "vex_source": "operator",
        "vex_suppressed": True,
        "suppressed": True,
        "suppression_state": "vex",
        "suppression_reason": "vex: compensating control recorded while the fix was scheduled",
    }


def refresh_report_finding_summary(report: dict[str, Any]) -> None:
    """Recount a serialized report's finding totals after its ``findings`` changed."""
    summary = _build_finding_summary([row for row in report.get("findings") or [] if isinstance(row, dict)])
    report["finding_summary"] = summary
    report["summary"] = {
        **(report.get("summary") or {}),
        "total_findings": summary["total"],
        "critical_unified_findings": summary["by_severity"]["critical"],
        "high_unified_findings": summary["by_severity"]["high"],
    }


def stage_report(report: dict[str, Any], index: int) -> dict[str, Any]:
    """The scan result of history stage ``index``; the last stage is the current report re-dated."""
    stages = history_stages()
    stage = stages[index]
    rows = [row for row in report.get("findings") or [] if isinstance(row, dict)]
    posture = [row for row in rows if _is_posture_row(row)]
    findings: list[dict[str, Any]] = []
    for row in rows:
        if not _is_posture_row(row):
            findings.append(row)
            continue
        arrival = _arrival_stage(row)
        if arrival > index:
            continue
        findings.append({**row, "first_seen": stages[arrival].timestamp} if arrival else row)
    for retired in _retired_rows(posture, len(stages)):
        if index >= retired.fixed_at:
            continue
        row = {**retired.row, "first_seen": retired.row.get("first_seen") or stages[0].timestamp}
        suppressed = retired.suppressed_from is not None and index >= retired.suppressed_from
        findings.append(_operator_vex(row) if suppressed else row)
    staged = {key: value for key, value in report.items() if key not in _CIS_SECTIONS}
    # Each stage's CIS benchmark states that stage's own CIS findings.
    staged.update(findings=findings, scan_id=stage.scan_id, **estate_cis_benchmarks(findings, recorded_cis_passes(report)))
    refresh_report_finding_summary(staged)
    if index == len(stages) - 1:
        # The current scan keeps its own evidence time, so it stays the newest job of its scope.
        return staged
    staged["generated_at"] = stage.timestamp
    scan_run = report.get("scan_run")
    if isinstance(scan_run, dict):
        staged["scan_run"] = {**scan_run, "scan_id": stage.scan_id, "generated_at": stage.timestamp}
    return staged


__all__ = ["HISTORY_SCOPE_ID", "HistoryStage", "history_stages", "refresh_report_finding_summary", "stage_report"]
