"""Audit log, vulnerability exception, baseline, trend, SIEM and issue-mapping routes."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, cast

import anyio.to_thread
from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse

from agent_bom.api.models import ExceptionRequest, IssueStatusUpdateRequest
from agent_bom.api.read_models import SiemConnectorsResponse, TrendsResponse, documented
from agent_bom.api.read_models.enterprise import (
    AuditEntriesResponse,
    AuditExportResponse,
    AuditIntegrityResponse,
    VulnExceptionResponse,
    VulnExceptionsResponse,
)
from agent_bom.api.routes.enterprise_routes._models import AuditExportVerifyRequest, _request_actor
from agent_bom.api.stores import _get_exception_store, _get_issue_mapping_store, _get_store, _get_trend_store
from agent_bom.api.suppression_approval import (
    ApprovalPersistenceError,
    SelfApprovalError,
    SuppressionApprovalRequest,
    exception_response,
    persist_approval,
)
from agent_bom.api.tenancy import require_body_tenant_match, require_request_tenant_id
from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_error, sanitize_text

router = APIRouter()
_logger = logging.getLogger("agent_bom.api.routes.enterprise")


# ── Audit Log ────────────────────────────────────────────────────────────────


@router.get("/audit", **documented(AuditEntriesResponse), tags=["enterprise"])
def list_audit_entries(
    request: Request,
    action: str | None = None,
    resource: str | None = None,
    since: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List audit log entries with optional filters."""
    from agent_bom.api.audit_log import get_audit_log

    tenant_id = require_request_tenant_id(request)
    store = get_audit_log()
    entries = store.list_entries(action=action, resource=resource, since=since, limit=limit, offset=offset, tenant_id=tenant_id)
    return {
        # schema_version on terminal list response.
        "schema_version": "v1",
        "entries": [e.to_dict() for e in entries],
        "total": store.count(action=action, resource=resource, since=since, tenant_id=tenant_id),
        "limit": limit,
        "offset": offset,
    }


def _configured_runtime_audit_log_path() -> Path | None:
    """Return the configured runtime proxy JSONL audit log, when readable."""
    log_env = env_raw("AGENT_BOM_LOG")
    if not log_env:
        return None
    path = Path(log_env).resolve()
    if path.is_file() and path.suffix == ".jsonl":
        return path
    return None


@router.get("/audit/integrity", **documented(AuditIntegrityResponse), tags=["enterprise"])
def audit_integrity(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=10_000)] = 1000,
    include_runtime: bool = True,
) -> dict:
    """Verify control-plane and runtime audit-chain integrity."""
    from agent_bom.api.audit_log import get_audit_log
    from agent_bom.audit_integrity import verify_audit_jsonl_chain

    tenant_id = require_request_tenant_id(request)
    verified, tampered = get_audit_log().verify_integrity(limit=limit, tenant_id=tenant_id)
    chains: list[dict[str, Any]] = [
        {
            "name": "control_plane",
            "algorithm": "hmac-sha256",
            "verified": verified,
            "tampered": tampered,
            "checked": verified + tampered,
            "tenant_scoped": True,
        }
    ]

    if include_runtime:
        runtime_log = _configured_runtime_audit_log_path()
        if runtime_log is not None:
            runtime = verify_audit_jsonl_chain(runtime_log, max_lines=limit)
            runtime_algorithms = list(runtime.get("algorithms") or ["unknown"])
            chains.append(
                {
                    "name": "runtime_proxy",
                    "algorithm": ",".join(runtime_algorithms),
                    "algorithms": runtime_algorithms,
                    "verified": int(runtime.get("verified", 0)),
                    "tampered": int(runtime.get("tampered", 0)),
                    "checked": int(runtime.get("checked", 0)),
                    "tenant_scoped": False,
                    "source": "AGENT_BOM_LOG",
                    "error": runtime.get("error", ""),
                }
            )

    total_verified = sum(int(chain["verified"]) for chain in chains)
    total_tampered = sum(int(chain["tampered"]) for chain in chains)
    algorithms = sorted({algorithm for chain in chains for algorithm in str(chain["algorithm"]).split(",") if algorithm})
    return {
        "verified": total_verified,
        "tampered": total_tampered,
        "checked": total_verified + total_tampered,
        "algorithms": algorithms,
        "chains": chains,
    }


@router.get("/audit/export", **documented(AuditExportResponse), tags=["enterprise"])
def export_audit_entries(
    request: Request,
    action: str | None = None,
    resource: str | None = None,
    since: str | None = None,
    limit: Annotated[int, Query(ge=1, le=10_000)] = 1000,
    offset: Annotated[int, Query(ge=0)] = 0,
    format: str = "json",
) -> Response:
    """Export audit entries as a signed evidence packet."""
    from agent_bom.api.audit_log import get_audit_log, log_action, sign_export_payload

    fmt = format.lower()
    if fmt not in {"json", "jsonl"}:
        raise HTTPException(status_code=400, detail="format must be one of: json, jsonl")

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = get_audit_log()
    entries = store.list_entries(action=action, resource=resource, since=since, limit=limit, offset=offset, tenant_id=tenant_id)
    verified, tampered = store.verify_integrity(limit=min(limit, 10_000), tenant_id=tenant_id)

    log_action(
        "audit.export",
        actor=actor,
        resource="audit/export",
        tenant_id=tenant_id,
        format=fmt,
        exported=len(entries),
        action_filter=action,
        resource_filter=resource,
    )

    if fmt == "jsonl":
        lines = [json.dumps(entry.to_dict(), sort_keys=True) for entry in entries]
        payload = ("\n".join(lines) + ("\n" if lines else "")).encode()
        return PlainTextResponse(
            content=payload.decode(),
            media_type="application/x-ndjson",
            headers={
                "Content-Disposition": 'attachment; filename="agent-bom-audit-export.jsonl"',
                "X-Agent-Bom-Audit-Export-Signature": sign_export_payload(payload),
            },
        )

    body = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "filters": {
            "action": action,
            "resource": resource,
            "since": since,
            "limit": limit,
            "offset": offset,
        },
        "integrity": {
            "verified": verified,
            "tampered": tampered,
            "checked": verified + tampered,
        },
        "entries": [entry.to_dict() for entry in entries],
    }
    payload = json.dumps(body, sort_keys=True).encode()
    return Response(
        content=payload,
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="agent-bom-audit-export.json"',
            "X-Agent-Bom-Audit-Export-Signature": sign_export_payload(payload),
        },
    )


@router.post("/audit/export/verify", tags=["enterprise"])
def verify_audit_export(request: Request, body: AuditExportVerifyRequest) -> dict:
    """Verify a signed audit export packet without returning HMAC key material."""
    from agent_bom.api.audit_log import log_action, verify_export_payload

    if isinstance(body.payload, str):
        payload = body.payload.encode("utf-8")
    else:
        payload = json.dumps(body.payload, sort_keys=True).encode("utf-8")

    valid = verify_export_payload(payload, body.signature)
    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    log_action(
        "audit.export_verify",
        actor=actor,
        resource="audit/export/verify",
        tenant_id=tenant_id,
        valid=valid,
        payload_bytes=len(payload),
    )
    return {"valid": valid, "payload_bytes": len(payload)}


# ── Exception / Waiver Management ────────────────────────────────────────────


@router.post("/exceptions", tags=["enterprise"], status_code=201)
def create_exception(request: Request, req: ExceptionRequest) -> dict:
    """Request a vulnerability exception / waiver."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import VulnException

    tenant_id = require_request_tenant_id(request)
    require_body_tenant_match(req.tenant_id, tenant_id)
    actor = _request_actor(request)
    exc = VulnException(
        vuln_id=req.vuln_id,
        package_name=req.package_name,
        server_name=req.server_name,
        reason=req.reason,
        requested_by=actor,
        expires_at=req.expires_at,
        tenant_id=tenant_id,
    )
    _get_exception_store().put(exc, tenant_id=tenant_id)
    log_action(
        "exception_create",
        actor=actor,
        resource=f"exception/{exc.exception_id}",
        tenant_id=tenant_id,
        vuln_id=req.vuln_id,
        package=req.package_name,
    )
    return exception_response(exc)


@router.get("/exceptions", **documented(VulnExceptionsResponse), tags=["enterprise"])
def list_exceptions(
    request: Request,
    status: str | None = None,
    # cap exception pagination to keep parity with /v1/audit.
    limit: Annotated[int, Query(ge=1, le=1000)] = 1000,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List all vulnerability exceptions."""
    tenant_id = require_request_tenant_id(request)
    all_exceptions = _get_exception_store().list_all(status=status, tenant_id=tenant_id)
    total = len(all_exceptions)
    page = all_exceptions[offset : offset + limit]
    return {
        # schema_version on terminal list response.
        "schema_version": "v1",
        "exceptions": [exception_response(e) for e in page],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/exceptions/{exception_id}", **documented(VulnExceptionResponse), tags=["enterprise"])
def get_exception(request: Request, exception_id: str) -> dict:
    """Get a specific exception."""
    tenant_id = require_request_tenant_id(request)
    exc = _get_exception_store().get(exception_id, tenant_id=tenant_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    return cast("dict[str, Any]", exception_response(exc))


@router.put("/exceptions/{exception_id}/approve", tags=["enterprise"])
def approve_exception(request: Request, exception_id: str, req: SuppressionApprovalRequest | None = None) -> dict:
    """Approve a pending exception (admin only)."""
    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = _get_exception_store()
    exc = store.get(exception_id, tenant_id=tenant_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    if getattr(request.state, "api_key_role", None) != "admin":
        raise HTTPException(status_code=403, detail="Suppression approval requires an authenticated admin")
    if req is not None and req.expires_at is not None:
        exc.expires_at = req.expires_at
    try:
        persist_approval(exc, store, actor=actor, tenant_id=tenant_id)
    except SelfApprovalError as error:
        raise HTTPException(status_code=403, detail=sanitize_error(error)) from None
    except ValueError as error:
        raise HTTPException(status_code=400, detail=sanitize_error(error)) from None
    except ApprovalPersistenceError:
        raise HTTPException(status_code=503, detail="Suppression approval persistence unavailable") from None
    return cast("dict[str, Any]", exception_response(exc))


@router.put("/exceptions/{exception_id}/revoke", tags=["enterprise"])
def revoke_exception(request: Request, exception_id: str) -> dict:
    """Revoke an active exception."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = _get_exception_store()
    exc = store.get(exception_id, tenant_id=tenant_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    exc.status = ExceptionStatus.REVOKED
    exc.revoked_at = datetime.now(timezone.utc).isoformat()
    store.put(exc, tenant_id=tenant_id)
    log_action("exception_revoke", actor=actor, resource=f"exception/{exception_id}", tenant_id=tenant_id)
    return cast("dict[str, Any]", exception_response(exc))


@router.delete("/exceptions/{exception_id}", tags=["enterprise"], status_code=204)
def delete_exception(request: Request, exception_id: str) -> None:
    """Delete an exception."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    store = _get_exception_store()
    exc = store.get(exception_id, tenant_id=tenant_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    ok = store.delete(exception_id, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    log_action("exception_delete", actor=actor, resource=f"exception/{exception_id}", tenant_id=tenant_id)


# ── Baseline Comparison & Trends ─────────────────────────────────────────────


@router.post("/baseline/compare", tags=["enterprise"])
def compare_baseline(
    request: Request,
    previous_job_id: Annotated[str, Query(min_length=1)],
    current_job_id: Annotated[str, Query(min_length=1)],
) -> dict:
    """Compare two scan results to show new, resolved, and persistent vulnerabilities."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.baseline import compare_reports

    store = _get_store()
    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    prev_job = store.get(previous_job_id, tenant_id=tenant_id)
    curr_job = store.get(current_job_id, tenant_id=tenant_id)
    if prev_job is None:
        raise HTTPException(status_code=404, detail="Previous job not found")
    if curr_job is None:
        raise HTTPException(status_code=404, detail="Current job not found")

    prev_report = prev_job.result or {}
    curr_report = curr_job.result or {}

    diff = compare_reports(prev_report, curr_report)
    log_action(
        "baseline.compare",
        actor=actor,
        resource="baseline/compare",
        tenant_id=tenant_id,
        previous_job_id=previous_job_id,
        current_job_id=current_job_id,
    )
    return diff.to_dict()


@router.get("/trends", **documented(TrendsResponse), tags=["enterprise"])
def get_trends(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=365)] = 30,
    days: Annotated[int | None, Query(ge=1, le=365)] = None,
    scope_id: Annotated[str | None, Query(max_length=256)] = None,
) -> dict:
    """Historical posture plus evidence-backed comparisons within a bounded window."""
    from datetime import datetime, timezone

    from agent_bom.api.audit_log import log_action
    from agent_bom.api.trend_comparison import parse_time, public_trend_point

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    history = _get_trend_store().get_history(limit=365, tenant_id=tenant_id)
    history.sort(key=lambda point: parse_time(point.timestamp) or datetime.min.replace(tzinfo=timezone.utc))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days) if days is not None else None
    previous_by_scope: dict[str, Any] = {}
    points = []
    for point in history:
        key = point.comparison_metadata.get("scope_id")
        previous = previous_by_scope.get(key) if key else None
        rendered = public_trend_point(point, previous)
        if key:
            previous_by_scope[key] = point
        observed = parse_time(point.timestamp)
        if scope_id is not None and key != scope_id:
            continue
        # Preserve legacy/invalid timestamp points without manufacturing dates.
        if cutoff is None or observed is None or observed >= cutoff:
            points.append(rendered)
    points = list(reversed(points))[:limit]
    log_action("trends.view", actor=actor, resource="trends", tenant_id=tenant_id, limit=limit)
    return {
        "data_points": points,
        "count": len(points),
        "days": days,
        "scope_id": scope_id,
        "available_scopes": sorted(previous_by_scope),
        "history_limited": len(history) == 365 or any(p.comparison_metadata.get("history_processing_limit") for p in history),
        "age_statistic": "median",
        "freshness_reference": "scan_completion",
    }


# ── SIEM Connectors ─────────────────────────────────────────────────────────


@router.get("/siem/connectors", **documented(SiemConnectorsResponse), tags=["enterprise"])
def list_siem_connectors() -> dict:
    """List available SIEM connector types."""
    from agent_bom.siem import list_connectors

    return {"connectors": list_connectors()}


@router.post("/siem/test", tags=["enterprise"])
async def test_siem_connection(
    request: Request,
    siem_type: str = "",
    url: str = "",
    token: str = Header(default="", alias="X-Siem-Token"),
) -> dict:
    """Test SIEM connectivity."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.security import validate_url
    from agent_bom.siem import SIEMConfig, create_connector

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"

    # Validate URL to prevent SSRF
    if url:
        try:
            validate_url(url)
        except Exception as url_exc:
            raise HTTPException(status_code=400, detail=f"Invalid URL: {sanitize_error(url_exc)}")

    try:

        def _probe() -> bool:
            connector = create_connector(siem_type, SIEMConfig(name=siem_type, url=url, token=token))
            return connector.health_check()

        healthy = await anyio.to_thread.run_sync(_probe)
        log_action(
            "siem.test",
            actor=actor,
            resource=f"siem/{siem_type or 'unknown'}",
            tenant_id=tenant_id,
            healthy=healthy,
            url=url,
        )
        return {"siem_type": siem_type, "healthy": healthy}
    except ValueError as exc:
        _logger.info("Invalid SIEM test request: %s", sanitize_text(sanitize_error(exc)))
        raise HTTPException(status_code=400, detail="Invalid SIEM connector request") from exc
    except Exception as exc:
        _logger.error(
            "Unexpected error while testing SIEM connection: %s",
            sanitize_text(sanitize_error(exc)),
        )
        log_action(
            "siem.test",
            actor=actor,
            resource=f"siem/{siem_type or 'unknown'}",
            tenant_id=tenant_id,
            healthy=False,
            error="Failed to test SIEM connection",
            url=url,
        )
        return {
            "siem_type": siem_type,
            "healthy": False,
            "error": "Failed to test SIEM connection",
        }


# ── Issue-mapping status ────────────────────────────────────────────────────
#
# Per-action Jira ticket creation (the old ``POST /v1/findings/jira`` with an
# ``X-Jira-Api-Token`` header) was retired in favour of the connect-once
# ticketing plane at ``/v1/ticketing`` (see routes/ticketing.py): a connection is
# configured once in the Connections hub and every action runs through the
# stored, encrypted connection — no credential is ever entered per action.


@router.put("/integrations/issues/{mapping_id}/status", tags=["enterprise"])
def update_issue_mapping_status(request: Request, mapping_id: str, req: IssueStatusUpdateRequest) -> dict:
    """Update tenant-scoped external issue mapping status after provider sync."""
    from agent_bom.api.audit_log import log_action

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    mapping = _get_issue_mapping_store().update_status(mapping_id, tenant_id=tenant_id, status=req.status)
    if not mapping:
        raise HTTPException(status_code=404, detail="Issue mapping not found")
    log_action(
        "integrations.issue_status_updated",
        actor=actor,
        resource=f"{mapping.provider}/{mapping.external_id}",
        tenant_id=tenant_id,
        issue_mapping_id=mapping.mapping_id,
        status=mapping.status,
    )
    return {"mapping": mapping.to_dict()}
