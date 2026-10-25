"""Operator-declared (emergency) advisories matched against stored inventory.

Endpoints:
    POST   /v1/intel/operator-advisories                       declare or replace an advisory (admin)
    GET    /v1/intel/operator-advisories                       list the tenant's advisories
    GET    /v1/intel/operator-advisories/matches               match all advisories against current scans
    GET    /v1/intel/operator-advisories/{advisory_id}/matches match one advisory
    DELETE /v1/intel/operator-advisories/{advisory_id}         retire an advisory (admin)

Matching reads the newest stored scan per target scope; nothing is rescanned.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.advisory_affected_read import persist_affected_answer, retire_advisory_findings, tenant_affected_answer
from agent_bom.api.audit_log import log_action
from agent_bom.api.findings_current import current_scan_jobs
from agent_bom.api.scan_finding_read import _completed_jobs_for_tenant
from agent_bom.api.stores import _get_operator_advisory_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.db.operator_advisories import distro_verdicts
from agent_bom.scanners.operator_advisory import OPERATOR_ADVISORY_PROVENANCE, OperatorAdvisory, match_advisories_against_reports

logger = logging.getLogger(__name__)
router = APIRouter()
_TAGS: list[str | Any] = ["intel"]


def _store() -> Any:
    return _get_operator_advisory_store()


def _current_reports(tenant_id: str) -> list[dict[str, Any]]:
    reports = []
    for job in current_scan_jobs(_completed_jobs_for_tenant(tenant_id), since=None, scan_id=None):
        result = dict(job.result or {})
        result.setdefault("scan_id", job.job_id)
        reports.append(result)
    return reports


def operator_advisory_matches(tenant_id: str, advisory_id: str | None = None) -> dict[str, Any] | None:
    """Transport-neutral match read shared by the REST route and the MCP tool; ``None`` when unknown."""
    rows = _store().list(tenant_id)
    if advisory_id is not None:
        rows = [row for row in rows if row.get("id") == advisory_id]
        if not rows:
            return None
    advisories = [OperatorAdvisory.model_validate({k: v for k, v in row.items() if k != "updated_at"}) for row in rows]
    with distro_verdicts() as verdict:
        result = match_advisories_against_reports(advisories, _current_reports(tenant_id), distro_verdict=verdict)
    return {
        "tenant_id": tenant_id,
        "advisory_ids": [a.id for a in advisories],
        "provenance": OPERATOR_ADVISORY_PROVENANCE,
        **result.to_dict(),
    }


@router.post("/intel/operator-advisories", tags=_TAGS, status_code=201)
def declare_operator_advisory(request: Request, body: OperatorAdvisory) -> dict:
    """Declare (or replace) an advisory ahead of feed publication."""
    tenant_id = require_request_tenant_id(request)
    record = _store().put(tenant_id, body.model_dump(mode="json"))
    actor = getattr(request.state, "api_key_name", "") or "system"
    log_action("operator_advisory.declare", actor=actor, resource=f"operator_advisory/{body.id}", tenant_id=tenant_id)
    return {**record, "provenance": OPERATOR_ADVISORY_PROVENANCE, "findings": _persist_findings(tenant_id, body.id)}


_PERSIST_FAILURES: tuple[type[BaseException], ...] = (OSError, RuntimeError, ValueError, KeyError, TypeError)


def _persist_findings(tenant_id: str, advisory_id: str) -> dict[str, Any]:
    """Match the declaration now so ``/v1/findings`` shows it; the declaration stands even if this fails."""
    try:
        answer = tenant_affected_answer(tenant_id, advisory_id)
        return {"status": "persisted", **persist_affected_answer(tenant_id, answer)} if answer else {"status": "skipped"}
    except _PERSIST_FAILURES:
        logger.warning("Operator advisory findings could not be persisted; the next re-match retries")
        return {"status": "deferred", "reason": "finding_store_unavailable"}


@router.get("/intel/operator-advisories", tags=_TAGS)
def list_operator_advisories(request: Request) -> dict:
    """List the tenant's operator-declared advisories."""
    tenant_id = require_request_tenant_id(request)
    store = _store()
    state = store.get_rematch_state(tenant_id) or {}
    rematch = {key: state.get(key) for key in ("last_run", "feed_cursor", "operator_cursor", "recent_findings")} if state else None
    return {"advisories": store.list(tenant_id), "provenance": OPERATOR_ADVISORY_PROVENANCE, "rematch": rematch}


@router.get("/intel/operator-advisories/matches", tags=_TAGS)
def match_all_operator_advisories(request: Request) -> dict:
    """Match every operator advisory against the tenant's current stored scans."""
    return operator_advisory_matches(require_request_tenant_id(request)) or {}


@router.get("/intel/operator-advisories/{advisory_id}/matches", tags=_TAGS)
def match_operator_advisory(request: Request, advisory_id: str) -> dict:
    """Match one operator advisory against the tenant's current stored scans."""
    body = operator_advisory_matches(require_request_tenant_id(request), advisory_id)
    if body is None:
        raise HTTPException(status_code=404, detail="Operator advisory not found")
    return body


@router.delete("/intel/operator-advisories/{advisory_id}", tags=_TAGS, status_code=204)
def delete_operator_advisory(request: Request, advisory_id: str) -> None:
    """Retire an operator advisory (for example once the feed record is authoritative)."""
    tenant_id = require_request_tenant_id(request)
    if not _store().delete(tenant_id, advisory_id):
        raise HTTPException(status_code=404, detail="Operator advisory not found")
    try:
        retire_advisory_findings(tenant_id, advisory_id)
    except _PERSIST_FAILURES:
        logger.warning("Operator advisory findings could not be retired; they resolve on the next re-match")
    actor = getattr(request.state, "api_key_name", "") or "system"
    log_action("operator_advisory.delete", actor=actor, resource=f"operator_advisory/{advisory_id}", tenant_id=tenant_id)
