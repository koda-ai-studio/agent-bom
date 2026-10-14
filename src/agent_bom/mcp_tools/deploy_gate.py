"""``should_i_deploy``: gate a candidate against every ranked path of the snapshot."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_bom.graph.attack_path_queue import AttackPathFilters, QueuePage
from agent_bom.graph.container import AttackPath
from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tools.exposure_queue import (
    RISK_SCALE,
    PathQuery,
    graph_evidence_scope,
    hydrate,
    nodes_for,
    pinned_identity,
    project_paths,
    summary_path,
    validate_request,
    whole_queue,
)

# Matched paths whose reachability is projected; beyond it the gate says so.
DEPLOY_EVALUATION_CAP = 250


@dataclass(slots=True)
class _Search:
    page: QueuePage
    generation: str
    matched: list[tuple[int, AttackPath]]
    projected: list[dict[str, Any]]
    stats: dict[str, Any]

    @property
    def complete(self) -> bool:
        return bool((self.page.ranked.ranking or {}).get("complete", True)) and not self.page.derivation_truncated


def _candidate_haystack(path: AttackPath, nodes_by_id: dict[str, Any]) -> list[str]:
    values = [
        path.source,
        path.target,
        path.summary,
        *path.hops,
        *path.vuln_ids,
        *path.finding_ids,
        *path.credential_exposure,
        *path.tool_exposure,
    ]
    for hop in path.hops:
        node = nodes_by_id.get(hop)
        if node is not None:
            values.append(str(getattr(node, "label", "") or ""))
    return [str(value).lower() for value in values if value]


def _decision_for_risk(risk: float, *, warn_risk: float, block_risk: float) -> str:
    if risk >= block_risk:
        return "block"
    if risk >= warn_risk:
        return "warn"
    return "allow"


def _validate(candidate: str, limit: int, warn_risk: float, block_risk: float, view: str, scan_id: str | None) -> str | None:
    if not candidate:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "candidate must not be empty", details={"argument": "candidate"})
    invalid = validate_request(limit, 25, PathQuery(), view)
    if invalid:
        return invalid
    if warn_risk < 0 or warn_risk > 100 or block_risk < 0 or block_risk > 100 or warn_risk > block_risk:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "warn_risk and block_risk must be ordered thresholds between 0 and 100",
            details={"warn_risk": warn_risk, "block_risk": block_risk},
        )
    if scan_id and "\x00" in scan_id:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Invalid graph snapshot identifier.")
    return None


async def _search(store: Any, tenant_id: str, scan_id: str | None, candidate: str) -> _Search | str:
    identity = await pinned_identity(store, tenant_id, scan_id)
    if isinstance(identity, str):
        return identity
    page = await whole_queue(store, tenant_id, identity[0], AttackPathFilters())
    ranked = page.ranked
    labels = {
        node.id: node for node in await nodes_for(store, tenant_id, ranked.scan_id, {hop for path in ranked.paths for hop in path.hops})
    }
    needle = candidate.lower()
    matched = [
        (index + 1, path) for index, path in enumerate(ranked.paths) if any(needle in value for value in _candidate_haystack(path, labels))
    ]
    evaluated = matched[:DEPLOY_EVALUATION_CAP]
    nodes, edges = await hydrate(store, tenant_id, ranked.scan_id, [path for _rank, path in evaluated])
    projected = project_paths(
        [path for _rank, path in evaluated],
        nodes=nodes,
        edges=edges,
        first_rank=1,
        scan_id=ranked.scan_id,
        ranks=[rank for rank, _path in evaluated],
    )
    stats = await asyncio.to_thread(store.snapshot_stats, tenant_id=tenant_id, scan_id=ranked.scan_id)
    return _Search(page, identity[1], matched, projected, stats)


def _verdict(search: _Search, *, warn_risk: float, block_risk: float) -> tuple[str, float | None, str, list[str]]:
    matched, projected = search.matched, search.projected
    max_risk = max((float(path.composite_risk or 0.0) for _rank, path in matched), default=None)
    decision = _decision_for_risk(max_risk, warn_risk=warn_risk, block_risk=block_risk) if max_risk is not None else "warn"
    evaluated = bool(matched) and len(matched) <= DEPLOY_EVALUATION_CAP
    evaluated = evaluated and all(path.get("reachability") in {"likely", "confirmed"} for path in projected)
    if decision == "allow" and (not evaluated or not search.complete):
        decision = "warn"
    reasons: list[str] = []
    if matched:
        top = projected[0]
        reasons.append(f"Top matched exposure path risk is {top.get('riskScore', 0)} for {top.get('label') or top.get('id')}.")
        findings = sorted({str(finding) for path in projected for finding in path.get("findings", []) if finding})
        if findings:
            reasons.append(f"Matched findings: {', '.join(findings[:5])}.")
        if not evaluated or not search.complete:
            reasons.append("Reachability is unverified or path evidence is incomplete; this is not an approval to deploy.")
    else:
        reasons.append("No matching exposure path evidence was found for the candidate; this is not an approval to deploy.")
    if not search.complete:
        reasons.append("Only part of the snapshot's paths could be searched; widen the graph budget before relying on this gate.")
    # Deliberately two-valued. A CI gate that needs to tell "no paths matched"
    # from "paths matched but reachability is unverified" reads matchedPathCount
    # alongside this; adding a third value here would break every consumer that
    # switches on the two.
    status = "evaluated" if evaluated and search.complete else "not_evaluated"
    return decision, max_risk, status, reasons


async def deploy_decision_for_tenant(
    *,
    candidate: str,
    tenant_id: str,
    scan_id: str | None = None,
    limit: int = 5,
    warn_risk: float = 40.0,
    block_risk: float = 80.0,
    view: str = "summary",
    _get_graph_store: Callable[[], Any],
    _resolve_scan: Callable[..., Any],
    _truncate_response: Callable[[str], str] | None = None,
) -> str:
    """Gate a candidate against every stored path of the pinned snapshot."""
    candidate_value = candidate.strip()
    invalid = _validate(candidate_value, limit, warn_risk, block_risk, view, scan_id)
    if invalid:
        return invalid
    scan_id, resolution_error = await _resolve_scan(tenant_id, scan_id)
    if resolution_error:
        return resolution_error
    search = await _search(_get_graph_store(), tenant_id, scan_id, candidate_value)
    if isinstance(search, str):
        return search
    decision, max_risk, status, reasons = _verdict(search, warn_risk=warn_risk, block_risk=block_risk)
    ranked = search.page.ranked
    shown = search.projected[:limit]
    payload = {
        "schema_version": "v1",
        "tool": "should_i_deploy",
        "tenant_id": tenant_id,
        **graph_evidence_scope(ranked.scan_id, search.generation, search.stats),
        "candidate": {"value": candidate_value},
        "decision": decision,
        "maxRisk": max_risk,
        "riskScale": RISK_SCALE,
        "evidenceStatus": status,
        "thresholds": {"warnRisk": warn_risk, "blockRisk": block_risk},
        "reasons": reasons,
        "searchedPaths": len(ranked.paths),
        "total": ranked.snapshot_total,
        "searchComplete": search.complete,
        "ranking": ranked.ranking,
        "matchedPathCount": len(search.matched),
        "returnedPathCount": len(shown),
        "view": view,
        "matchedPaths": [summary_path(path) for path in shown] if view == "summary" else shown,
        "provenance": {
            "source": "mcp_should_i_deploy",
            "basis": "exposure_paths" if search.matched else "no_matching_exposure_path_evidence",
            "pathSource": search.page.source,
        },
    }
    encoded = json.dumps(payload, separators=(",", ":"), default=str)
    return _truncate_response(encoded) if _truncate_response is not None else encoded


__all__ = ["DEPLOY_EVALUATION_CAP", "deploy_decision_for_tenant"]
