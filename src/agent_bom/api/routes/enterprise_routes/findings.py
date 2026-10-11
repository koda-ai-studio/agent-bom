"""Finding feedback, triage and false-positive routes plus the tenant triage indexes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.models import FalsePositiveRequest, FindingFeedbackRequest, FindingTriageDecisionRequest, FindingTriageRequest
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.enterprise import FalsePositivesResponse, FindingFeedbackResponse, FindingTriageResponse
from agent_bom.api.routes.enterprise_routes._models import (
    TriageOwnerIndex,
    TriageStateIndex,
    _feedback_reason,
    _feedback_response,
    _parse_feedback_reason,
    _parse_triage_reason,
    _request_actor,
    _triage_reason,
    _triage_response,
    _validate_triage_decision,
)
from agent_bom.api.stores import _get_exception_store
from agent_bom.api.suppression_approval import reset_suppression_request, suppression_active
from agent_bom.api.tenancy import require_request_tenant_id

router = APIRouter()
# Registered after the facade's VEX routes so route order is unchanged.
tail_router = APIRouter()


def build_tenant_triage_state_index(tenant_id: str) -> TriageStateIndex:
    """Return the tenant's newest active triage state per match key."""
    index: TriageStateIndex = {}
    for sequence, exc in enumerate(_get_exception_store().list_all(tenant_id=tenant_id)):
        if _parse_triage_reason(str(exc.reason)) is None:
            continue
        if exc.status.value in {"revoked", "rejected"} or (exc.expires_at and exc.is_expired()):
            continue
        key = (str(exc.vuln_id), str(exc.package_name), str(exc.server_name))
        index.setdefault(key, (sequence, _triage_response(exc)))
    return index


def triage_state_for(
    index: TriageStateIndex,
    *,
    vuln_id: str,
    package: str,
    server_name: str = "",
) -> dict[str, Any] | None:
    """Return the newest active triage state matching one finding."""
    candidates: list[tuple[int, dict[str, Any]]] = []
    server_keys = tuple(dict.fromkeys((server_name, "*", "")))
    for candidate_vuln in (vuln_id, "*"):
        for candidate_package in (package, "*"):
            for candidate_server in server_keys:
                candidate = index.get((candidate_vuln, candidate_package, candidate_server))
                if candidate is not None:
                    candidates.append(candidate)
    if not candidates:
        return None
    return dict(min(candidates, key=lambda item: item[0])[1])


def build_tenant_triage_owner_index(tenant_id: str) -> TriageOwnerIndex:
    """Return a constant-time match index for the tenant's triage entries.

    The finding "owner" is the triage ``assignee``. Only triage entries with an
    assignee contribute — suppressions and feedback carry an approver, not an
    owner, and must not be surfaced as ownership. Tenant-scoped read: the store
    is queried with ``tenant_id`` so one tenant's assignees never leak into
    another tenant's findings.
    """
    index: TriageOwnerIndex = {}
    for sequence, exc in enumerate(_get_exception_store().list_all(tenant_id=tenant_id)):
        data = _parse_triage_reason(str(exc.reason))
        if data is None:
            continue
        if exc.status.value in {"revoked", "rejected"} or (exc.expires_at and exc.is_expired()):
            continue
        assignee = str(data.get("assignee") or getattr(exc, "approved_by", "") or "").strip()
        if assignee:
            # ``list_all`` is newest-first. Keep only its first entry per match
            # key, while retaining the sequence so exact/wildcard candidates can
            # preserve that same global newest-first winner without scanning all
            # triage rows once per finding.
            key = (str(exc.vuln_id), str(exc.package_name), str(exc.server_name))
            index.setdefault(key, (sequence, assignee))
    return index


def triage_owner_for(
    index: TriageOwnerIndex,
    *,
    vuln_id: str,
    package: str,
    server_name: str = "",
) -> str | None:
    """Return the triage assignee matching a finding, or ``None`` when unassigned."""
    candidates: list[tuple[int, str]] = []
    # Vuln/package each accept exact or ``*``. Server additionally accepts the
    # historical empty-string wildcard. Eight/twelve bounded dictionary reads
    # replace the previous O(findings * tenant triage rows) join.
    server_keys = tuple(dict.fromkeys((server_name, "*", "")))
    for candidate_vuln in (vuln_id, "*"):
        for candidate_package in (package, "*"):
            for candidate_server in server_keys:
                candidate = index.get((candidate_vuln, candidate_package, candidate_server))
                if candidate is not None:
                    candidates.append(candidate)
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


# ── False Positive Management ────────────────────────────────────────────────


@router.post("/findings/false-positive", tags=["enterprise"], status_code=201)
def mark_false_positive(request: Request, req: FalsePositiveRequest) -> dict:
    """Mark a finding as false positive."""
    feedback = create_finding_feedback(
        request,
        FindingFeedbackRequest(
            vulnerability_id=req.vulnerability_id,
            package=req.package,
            state="false_positive",
            reason=req.reason,
            server_name="",
            expires_at="",
        ),
    )
    return {
        "id": feedback["id"],
        "vulnerability_id": feedback["vulnerability_id"],
        "package": feedback["package"],
        "reason": feedback["reason"],
        "marked_by": feedback["marked_by"],
        "status": feedback["status"],
        "created_at": feedback["created_at"],
    }


@router.post("/findings/feedback", tags=["enterprise"], status_code=201)
def create_finding_feedback(request: Request, req: FindingFeedbackRequest) -> dict:
    """Record tenant-scoped finding feedback or suppression state."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus, VulnException

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    exc = VulnException(
        vuln_id=req.vulnerability_id,
        package_name=req.package,
        server_name=req.server_name,
        reason=_feedback_reason(req.state, req.reason),
        requested_by=actor,
        status=ExceptionStatus.PENDING,
        expires_at=req.expires_at,
        tenant_id=tenant_id,
    )
    _get_exception_store().put(exc, tenant_id=tenant_id)
    log_action(
        "findings.feedback_recorded",
        actor=actor,
        resource=f"finding-feedback/{exc.exception_id}",
        tenant_id=tenant_id,
        vuln_id=req.vulnerability_id,
        package=req.package,
        state=req.state,
        expires_at=req.expires_at,
    )
    return _feedback_response(exc)


@router.get("/findings/feedback", **documented(FindingFeedbackResponse), tags=["enterprise"])
def list_finding_feedback(request: Request, state: str | None = None) -> dict:
    """List tenant-scoped finding feedback entries."""
    tenant_id = require_request_tenant_id(request)
    entries = []
    for exc in _get_exception_store().list_all(tenant_id=tenant_id):
        parsed = _parse_feedback_reason(exc.reason)
        if parsed is None:
            continue
        entry_state, _ = parsed
        if state and entry_state != state:
            continue
        entries.append(_feedback_response(exc))
    return {"feedback": entries, "total": len(entries)}


def record_finding_triage(*, tenant_id: str, actor: str, req: FindingTriageRequest) -> dict[str, Any]:
    """Persist a tenant-scoped triage decision to the exception store.

    Shared by ``POST /v1/findings/triage`` and the MCP ``findings_triage`` write
    tool so both surfaces write identical entries to the one exception store.
    Raises ``HTTPException(400)`` when a ``not_affected`` decision omits its
    required OpenVEX justification.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus, VulnException

    _validate_triage_decision(req.decision, req.justification)
    now = datetime.now(timezone.utc).isoformat()
    queue_state = "decided" if req.decision in {"affected", "not_affected"} else req.queue_state
    reviewed_at = now if queue_state == "decided" else ""
    exc = VulnException(
        vuln_id=req.vulnerability_id,
        package_name=req.package,
        server_name=req.server_name,
        reason=_triage_reason(
            {
                "queue_state": queue_state,
                "decision": req.decision,
                "justification": req.justification,
                "decision_reason": req.decision_reason,
                "assignee": req.assignee,
                "reviewed_at": reviewed_at,
            }
        ),
        requested_by=actor,
        approved_by="",
        status=ExceptionStatus.PENDING,
        expires_at=req.expires_at,
        approved_at="",
        tenant_id=tenant_id,
    )
    _get_exception_store().put(exc, tenant_id=tenant_id)
    log_action(
        "findings.triage_created",
        actor=actor,
        resource=f"finding-triage/{exc.exception_id}",
        tenant_id=tenant_id,
        vuln_id=req.vulnerability_id,
        package=req.package,
        queue_state=queue_state,
        decision=req.decision,
    )
    return _triage_response(exc)


@router.post("/findings/triage", tags=["enterprise"], status_code=201)
def create_finding_triage(request: Request, req: FindingTriageRequest) -> dict:
    """Create a tenant-scoped finding triage queue item."""
    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    return record_finding_triage(tenant_id=tenant_id, actor=actor, req=req)


@router.get("/findings/triage", **documented(FindingTriageResponse), tags=["enterprise"])
def list_finding_triage(
    request: Request,
    queue_state: str | None = None,
    decision: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 1000,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List tenant-scoped finding triage queue items."""
    tenant_id = require_request_tenant_id(request)
    entries = []
    for exc in _get_exception_store().list_all(tenant_id=tenant_id):
        data = _parse_triage_reason(exc.reason)
        if data is None:
            continue
        response = _triage_response(exc)
        if queue_state and response["queue_state"] != queue_state:
            continue
        if decision and response["decision"] != decision:
            continue
        entries.append(response)
    total = len(entries)
    return {
        "schema_version": "findings.triage.v1",
        "triage": entries[offset : offset + limit],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.put("/findings/triage/{triage_id}/decision", tags=["enterprise"])
def update_finding_triage_decision(request: Request, triage_id: str, req: FindingTriageDecisionRequest) -> dict:
    """Record a finding triage decision and review timestamp."""
    from agent_bom.api.audit_log import log_action

    _validate_triage_decision(req.decision, req.justification)
    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    store = _get_exception_store()
    exc = store.get(triage_id, tenant_id=tenant_id)
    if exc is None or _parse_triage_reason(exc.reason) is None:
        raise HTTPException(status_code=404, detail=f"Finding triage item {triage_id} not found")
    reviewed_at = datetime.now(timezone.utc).isoformat()
    current = _parse_triage_reason(exc.reason) or {}
    assignee = req.assignee if req.assignee is not None else str(current.get("assignee") or exc.approved_by or "")
    exc.reason = _triage_reason(
        {
            "queue_state": "decided",
            "decision": req.decision,
            "justification": req.justification,
            "decision_reason": req.decision_reason,
            "assignee": assignee,
            "reviewed_at": reviewed_at,
        }
    )
    reset_suppression_request(exc, decided_by=actor)
    if req.expires_at is not None:
        exc.expires_at = req.expires_at
    store.put(exc, tenant_id=tenant_id)
    log_action(
        "findings.triage_decision_recorded",
        actor=actor,
        resource=f"finding-triage/{triage_id}",
        tenant_id=tenant_id,
        vuln_id=exc.vuln_id,
        package=exc.package_name,
        decision=req.decision,
    )
    return _triage_response(exc)


@tail_router.get("/findings/false-positives", **documented(FalsePositivesResponse), tags=["enterprise"])
def list_false_positives(request: Request) -> dict:
    """List all false positive entries."""
    tenant_id = require_request_tenant_id(request)
    all_exceptions = _get_exception_store().list_all(tenant_id=tenant_id)
    fps = [e for e in all_exceptions if (_parse_feedback_reason(e.reason) or ("", ""))[0] == "false_positive"]
    return {
        "false_positives": [
            {
                "id": e.exception_id,
                "vulnerability_id": e.vuln_id,
                "package": e.package_name,
                "reason": (_parse_feedback_reason(e.reason) or ("false_positive", e.reason))[1],
                "marked_by": e.requested_by,
                "status": "suppressed" if suppression_active(e) else "pending",
                "created_at": e.created_at,
            }
            for e in fps
        ],
        "total": len(fps),
    }


@tail_router.delete("/findings/false-positive/{fp_id}", tags=["enterprise"], status_code=204)
def remove_false_positive(request: Request, fp_id: str) -> None:
    """Un-mark a false positive."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    store = _get_exception_store()
    exc = store.get(fp_id, tenant_id=tenant_id)
    if exc is None or (_parse_feedback_reason(exc.reason) or ("", ""))[0] != "false_positive":
        raise HTTPException(status_code=404, detail=f"False positive {fp_id} not found")
    ok = store.delete(fp_id, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"False positive {fp_id} not found")
    log_action("findings.false_positive_removed", actor=actor, resource=f"fp/{fp_id}", tenant_id=tenant_id)


@tail_router.delete("/findings/feedback/{feedback_id}", tags=["enterprise"], status_code=204)
def remove_finding_feedback(request: Request, feedback_id: str) -> None:
    """Remove tenant-scoped finding feedback without deleting audit history."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    store = _get_exception_store()
    exc = store.get(feedback_id, tenant_id=tenant_id)
    if exc is None or _parse_feedback_reason(exc.reason) is None:
        raise HTTPException(status_code=404, detail=f"Finding feedback {feedback_id} not found")
    ok = store.delete(feedback_id, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Finding feedback {feedback_id} not found")
    log_action("findings.feedback_removed", actor=actor, resource=f"finding-feedback/{feedback_id}", tenant_id=tenant_id)
