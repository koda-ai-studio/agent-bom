"""Answer analysis tools from the session's own scan result before any persisted snapshot.

A stdio session that just ran ``scan`` holds the freshest evidence about the
project it scanned. ``blast_radius``, ``should_i_deploy`` and ``exposure_paths``
read that result (explicit ``result_id`` or the caller's newest) before the
tenant's persisted graph, and label the answer ``session_scan_result`` so a
consumer can tell it from control-plane evidence.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_bom.mcp_tools.result_store import ResultStore
from agent_bom.mcp_tools.scan_response import SCAN_RESULTS

SESSION_SOURCE = "session_scan_result"
# Report ``riskScore`` / ``risk_score`` are 0-10; the deploy gate thresholds are 0-100.
_RISK_SCALE_FACTOR = 10.0
_PATH_SUMMARY_KEYS = ("id", "rank", "label", "summary", "severity", "riskScore", "fix", "findings", "source", "target", "suppressed")


class SessionResultError(ValueError):
    """An explicit ``result_id`` that names no readable stored result."""


def _store(store: ResultStore | None) -> ResultStore:
    return store if store is not None else SCAN_RESULTS


def load_session_report(*, owner: str, result_id: str | None, store: ResultStore | None = None) -> tuple[str, dict[str, Any]] | None:
    """The stored report for ``result_id``, or the caller's newest one; ``None`` when the session has none."""
    backing = _store(store)
    wanted = (result_id or "").strip()
    if wanted:
        stored = backing.get(owner, wanted)
        if stored is None or not isinstance(stored.get("report"), dict):
            raise SessionResultError(
                "Unknown or expired result_id. Results are kept for a limited time per tenant and per caller; run scan again."
            )
        return wanted, stored["report"]
    latest = backing.latest(owner)
    if latest is None:
        return None
    found_id, stored = latest
    report = stored.get("report") if isinstance(stored, dict) else None
    return (found_id, report) if isinstance(report, dict) else None


async def load_session_report_async(
    *, owner: str, result_id: str | None, store: ResultStore | None = None
) -> tuple[str, dict[str, Any]] | None:
    return await asyncio.to_thread(load_session_report, owner=owner, result_id=result_id, store=store)


def _rows(report: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = report.get(key)
    if key == "exposure_paths" and isinstance(value, dict):
        value = value.get("paths")
    return [row for row in (value if isinstance(value, list) else []) if isinstance(row, dict)]


def _strings(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list | tuple | set) else []


def _advisory(row: dict[str, Any]) -> str:
    return str(row.get("vulnerability_id") or row.get("cve_id") or "").strip()


def _package_label(row: dict[str, Any]) -> str:
    name, version = str(row.get("package_name") or ""), str(row.get("package_version") or "")
    return f"{name}@{version}" if name and version else name or str(row.get("package") or "")


# ── blast_radius ─────────────────────────────────────────────────────────────


def session_blast_radius(report: dict[str, Any], result_id: str, cve_id: str) -> dict[str, Any] | None:
    """The report's blast-radius rows for one advisory in the legacy row shape; ``None`` when absent."""
    matches = [row for row in _rows(report, "blast_radius") if _advisory(row).upper() == cve_id.upper()]
    if not matches:
        return None
    open_rows = [row for row in matches if row.get("suppressed") is not True]
    results = [
        {
            "cve_id": _advisory(row),
            "severity": row.get("severity") or "unknown",
            "cvss_score": row.get("cvss_score"),
            "risk_score": row.get("risk_score") or 0,
            "package": _package_label(row),
            "ecosystem": row.get("ecosystem"),
            "affected_servers": _strings(row.get("affected_servers")),
            "affected_agents": _strings(row.get("affected_agents")),
            "exposed_credentials": _strings(row.get("exposed_credentials")),
            "exposed_tools": _strings(row.get("exposed_tools")),
            "fixed_version": row.get("fixed_version"),
            "ai_risk_context": row.get("ai_risk_context"),
            "exposure_path_id": row.get("exposure_path_id"),
            "reachability": row.get("reachability"),
            "is_kev": row.get("is_kev"),
        }
        for row in open_rows
    ]
    return {
        "cve_id": cve_id,
        "found": True,
        "source": SESSION_SOURCE,
        "result_id": result_id,
        "scope": {"tenant_id": None, "scan_id": report.get("scan_id")},
        "count": len(results),
        "suppressed_count": len(matches) - len(open_rows),
        "count_basis": "open_occurrences",
        "completeness": {"status": "complete", "reason": f"session scan result {result_id}"},
        "blast_radii": results,
    }


# ── should_i_deploy ──────────────────────────────────────────────────────────


def _path_keys(path: dict[str, Any]) -> set[str]:
    """Every exact identifier a candidate may name on a report exposure path."""
    values: set[str] = set()
    for key in ("id", "label", "source", "target", "fix"):
        value = path.get(key)
        if isinstance(value, str):
            values.add(value)
    for key in ("hops", "nodeIds", "findings", "affectedServers", "affectedAgents"):
        values.update(_strings(path.get(key)))
    labels = path.get("nodeLabels")
    if isinstance(labels, dict):
        values.update(str(label) for label in labels.values())
    for hop in list(values):
        if hop.startswith("pkg:"):
            coordinate = hop.split(":", 2)[-1]  # pkg:<ecosystem>:<name>@<version>
            values.add(coordinate)
            head, sep, _version = coordinate.rpartition("@")
            if sep and head:
                values.add(head)
    values.discard("fix")
    return {value.strip().lower() for value in values if value.strip()}


def _blast_keys(row: dict[str, Any]) -> set[str]:
    values = {_advisory(row), _package_label(row), str(row.get("package_name") or ""), str(row.get("exposure_path_id") or "")}
    values.update(_strings(row.get("affected_servers")))
    values.update(_strings(row.get("affected_agents")))
    return {value.strip().lower() for value in values if value.strip()}


def _risk_100(value: Any) -> float:
    try:
        return round(float(value or 0.0) * _RISK_SCALE_FACTOR, 1)
    except (TypeError, ValueError):
        return 0.0


def _blocking(path: dict[str, Any], rows_by_path: dict[str, dict[str, Any]]) -> bool:
    """A KEV finding reached from an agent with credential exposure, not disproven."""
    row = rows_by_path.get(str(path.get("id") or ""), {})
    reachability = str(path.get("reachability") or row.get("reachability") or "").lower()
    is_kev = bool(path.get("isKev")) or bool(row.get("is_kev"))
    from_agent = str(path.get("source") or "").startswith("agent:")
    credentials = _strings(path.get("exposedCredentials")) or _strings(row.get("exposed_credentials"))
    return reachability != "unlikely" and is_kev and from_agent and bool(credentials)


def _decision(risk: float, *, warn_risk: float, block_risk: float) -> str:
    if risk >= block_risk:
        return "block"
    if risk >= warn_risk:
        return "warn"
    return "allow"


def _matched_paths(report: dict[str, Any], needle: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Open exposure paths naming ``needle`` exactly, plus rows whose path the report omitted."""
    paths = [path for path in _rows(report, "exposure_paths") if path.get("suppressed") is not True]
    rows = [row for row in _rows(report, "blast_radius") if row.get("suppressed") is not True]
    rows_by_path = {str(row.get("exposure_path_id") or ""): row for row in rows}
    matched = [path for path in paths if needle in _path_keys(path)]
    matched_ids = {str(path.get("id") or "") for path in matched}
    for row in rows:
        path_id = str(row.get("exposure_path_id") or "")
        if needle in _blast_keys(row) and path_id and path_id not in matched_ids:
            matched_ids.add(path_id)
            matched.append(
                {
                    "id": path_id,
                    "rank": row.get("exposure_path_rank"),
                    "label": f"{_package_label(row)} -> {_advisory(row)}",
                    "severity": row.get("severity"),
                    "riskScore": row.get("risk_score"),
                    "fix": f"Upgrade {row.get('package_name')} to {row['fixed_version']}" if row.get("fixed_version") else None,
                    "findings": [_advisory(row)],
                    "source": None,
                    "target": f"vuln:{_advisory(row)}",
                    "exposedCredentials": _strings(row.get("exposed_credentials")),
                }
            )
    matched.sort(key=lambda path: (-(_risk_100(path.get("riskScore"))), str(path.get("id") or "")))
    return paths, matched, rows_by_path


def _verdict(
    matched: list[dict[str, Any]], rows_by_path: dict[str, dict[str, Any]], *, warn_risk: float, block_risk: float, result_id: str
) -> tuple[str, float, bool, list[str]]:
    """Decision, max risk (0-100), whether reachability was evaluated, and the reasons."""
    max_risk = max(_risk_100(path.get("riskScore")) for path in matched)
    blocking = [path for path in matched if _blocking(path, rows_by_path)]
    reach = [str(path.get("reachability") or rows_by_path.get(str(path.get("id") or ""), {}).get("reachability") or "") for path in matched]
    evaluated = all(value in {"likely", "confirmed"} for value in reach)
    decision = _decision(max_risk, warn_risk=warn_risk, block_risk=block_risk)
    if blocking:
        decision = "block"
    if decision == "allow" and not evaluated:
        decision = "warn"
    top = matched[0]
    reasons = [f"Top matched exposure path risk is {_risk_100(top.get('riskScore'))} for {top.get('label') or top.get('id')}."]
    if blocking:
        reasons.append(
            f"{len(blocking)} matched path(s) reach a CISA KEV finding from an agent with credential exposure; "
            "blocked until reachability evidence rules the path out."
        )
    findings = sorted({str(finding) for path in matched for finding in _strings(path.get("findings")) if finding})
    if findings:
        reasons.append(f"Matched findings: {', '.join(findings[:5])}.")
    if not evaluated:
        reasons.append("Reachability is unverified or path evidence is incomplete; this is not an approval to deploy.")
    reasons.append(f"Evidence is the session scan result {result_id}, not the tenant's persisted estate graph.")
    return decision, max_risk, evaluated, reasons


def session_deploy_decision(
    report: dict[str, Any],
    result_id: str,
    *,
    candidate: str,
    tenant_id: str,
    limit: int,
    warn_risk: float,
    block_risk: float,
    view: str,
) -> dict[str, Any] | None:
    """Gate ``candidate`` against the report's exposure paths; ``None`` when nothing names it."""
    paths, matched, rows_by_path = _matched_paths(report, candidate.strip().lower())
    if not matched:
        return None
    decision, max_risk, evaluated, reasons = _verdict(
        matched, rows_by_path, warn_risk=warn_risk, block_risk=block_risk, result_id=result_id
    )
    shown = matched[:limit]
    return {
        "schema_version": "v1",
        "tool": "should_i_deploy",
        "tenant_id": tenant_id,
        "scan_id": report.get("scan_id"),
        "result_id": result_id,
        "evidence_scope": SESSION_SOURCE,
        "snapshot_generation": None,
        "collection_coverage": {"status": "session_scan", "scan_sources": report.get("scan_sources")},
        "candidate": {"value": candidate.strip()},
        "decision": decision,
        "maxRisk": max_risk,
        "riskScale": {"riskScore": "0-100 (report risk_score x 10)"},
        "evidenceStatus": "evaluated" if evaluated else "not_evaluated",
        "thresholds": {"warnRisk": warn_risk, "blockRisk": block_risk},
        "reasons": reasons,
        "searchedPaths": len(paths),
        "matchingTotal": len(matched),
        "total": len(paths),
        "searchComplete": True,
        "ranking": {"order": ["exposure_path_rank"]},
        "matchedPathCount": len(matched),
        "returnedPathCount": len(shown),
        "view": view,
        "matchedPaths": [{key: path.get(key) for key in _PATH_SUMMARY_KEYS if key in path} for path in shown]
        if view == "summary"
        else shown,
        "provenance": {"source": "mcp_should_i_deploy", "basis": SESSION_SOURCE, "pathSource": "scan_result_exposure_paths"},
    }


__all__ = [
    "SESSION_SOURCE",
    "SessionResultError",
    "load_session_report",
    "load_session_report_async",
    "session_blast_radius",
    "session_deploy_decision",
]
