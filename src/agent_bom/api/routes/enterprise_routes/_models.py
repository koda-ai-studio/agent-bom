"""Request models, triage/feedback reason helpers and shared enterprise route constants."""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from agent_bom.api.suppression_approval import suppression_active, suppression_requested, suppression_review_fields


class BrowserSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_key: str = Field(
        ...,
        min_length=1,
        description="API key to exchange for a same-origin httpOnly browser session cookie",
    )


class ManagedTrialInvitationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(..., min_length=3, max_length=254)
    organization: str = Field(..., min_length=1, max_length=128)


class ManagedTrialOIDCStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: SecretStr


class AuditExportVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: Any = Field(..., description="Audit export payload object, JSON string, or JSONL text")
    signature: str = Field(..., min_length=64, max_length=128, description="X-Agent-Bom-Audit-Export-Signature value")


_FEEDBACK_PREFIX = "[finding_feedback:"
_TRIAGE_PREFIX = "[finding_triage]"
_LEGACY_FALSE_POSITIVE_PREFIX = "[false_positive]"


def _request_actor(request: Request) -> str:
    return str(getattr(request.state, "api_key_name", None) or getattr(request.state, "auth_method", None) or "system")


def _feedback_reason(state: str, reason: str) -> str:
    clean_state = state.strip().lower().replace("-", "_")
    if clean_state == "not_applicable":
        clean_state = "not_affected"
    clean_reason = reason.strip()
    return f"{_FEEDBACK_PREFIX}{clean_state}] {clean_reason}".strip()


def _parse_feedback_reason(reason: str) -> tuple[str, str] | None:
    if reason.startswith(_FEEDBACK_PREFIX):
        close = reason.find("]")
        if close > len(_FEEDBACK_PREFIX):
            state = reason[len(_FEEDBACK_PREFIX) : close].strip().lower()
            if state == "not_applicable":
                state = "not_affected"
            return state, reason[close + 1 :].strip()
    if reason.startswith(_LEGACY_FALSE_POSITIVE_PREFIX):
        return "false_positive", reason.removeprefix(_LEGACY_FALSE_POSITIVE_PREFIX).strip()
    return None


def _validate_triage_decision(decision: str, justification: str | None) -> None:
    if decision == "not_affected" and not justification:
        raise HTTPException(status_code=400, detail="not_affected triage decisions require an OpenVEX justification")


def _triage_reason(payload: dict[str, Any]) -> str:
    return f"{_TRIAGE_PREFIX} {json.dumps(payload, sort_keys=True, separators=(',', ':'))}"


def _parse_triage_reason(reason: str) -> dict[str, Any] | None:
    if not reason.startswith(_TRIAGE_PREFIX):
        return None
    raw = reason.removeprefix(_TRIAGE_PREFIX).strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _feedback_response(exc: Any) -> dict[str, Any]:
    parsed = _parse_feedback_reason(str(exc.reason))
    state, reason = parsed if parsed else ("unknown", str(exc.reason))
    return {
        "id": exc.exception_id,
        "vulnerability_id": exc.vuln_id,
        "package": exc.package_name,
        "server_name": exc.server_name,
        "state": state,
        "reason": reason,
        "marked_by": exc.requested_by,
        "status": "suppressed" if suppression_active(exc) else ("pending" if suppression_requested(exc) else state),
        "created_at": exc.created_at,
        "expires_at": exc.expires_at,
        "tenant_id": exc.tenant_id,
    }


def _triage_response(exc: Any) -> dict[str, Any]:
    data = _parse_triage_reason(str(exc.reason)) or {}
    decision = str(data.get("decision") or "under_investigation")
    queue_state = str(data.get("queue_state") or "open")
    reviewed_at = str(data.get("reviewed_at") or exc.approved_at or "")
    return {
        "id": exc.exception_id,
        "vulnerability_id": exc.vuln_id,
        "package": exc.package_name,
        "server_name": exc.server_name,
        "queue_state": queue_state,
        "decision": decision,
        "justification": data.get("justification"),
        "decision_reason": str(data.get("decision_reason") or ""),
        "assignee": str(data.get("assignee") or exc.approved_by or ""),
        "created_by": exc.requested_by,
        "created_at": exc.created_at,
        "reviewed_at": reviewed_at,
        "expires_at": exc.expires_at,
        "tenant_id": exc.tenant_id,
        "vex_eligible": suppression_active(exc) and decision == "not_affected" and bool(data.get("justification")),
        **suppression_review_fields(exc),
    }


TriageOwnerKey = tuple[str, str, str]
TriageOwnerIndex = dict[TriageOwnerKey, tuple[int, str]]
TriageStateIndex = dict[TriageOwnerKey, tuple[int, dict[str, Any]]]
