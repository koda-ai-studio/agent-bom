"""Request checks for API surfaces that spend the server's own credentials.

A Kubernetes service account or kubeconfig, SaaS connector tokens, an
``HF_TOKEN`` or a Snowflake identity configured on the API process belong to
the operator, not to whichever tenant sends a request. Every such surface needs
three things: an operator opt-in flag, a caller with the admin-only
``cloud_ambient`` permission, and (when the operator binds one) the owning
tenant. Execution-time rechecks use :func:`ambient_scan_refusal`, which has no
caller and so checks only the flags and the tenant binding.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.cloud.ambient_credentials import (
    API_CONNECTOR_SCANS_ENV,
    API_K8S_SCANS_ENV,
    ambient_disabled_note,
    ambient_tenant_permitted,
    api_connector_scans_enabled,
    api_k8s_scans_enabled,
)
from agent_bom.rbac import Role, check_permission

ADMIN_ONLY_NOTE = "This uses the control plane's own credentials and is limited to admins of the tenant that owns them."
TENANT_NOT_PERMITTED_NOTE = "This tenant may not use the control plane's own credentials."
K8S_SURFACE = "Kubernetes scanning with the API server's service account or kubeconfig"
CONNECTOR_SURFACE = "SaaS connector discovery with the API server's tokens"


def _request_tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def caller_may_use_ambient(request: Request) -> bool:
    """Admin-only ``cloud_ambient`` permission inside the permitted tenant."""
    try:
        role = Role(str(getattr(request.state, "api_key_role", "") or "").lower())
    except ValueError:
        return False
    return check_permission(role, "cloud_ambient") and ambient_tenant_permitted(_request_tenant(request))


def _field(body: Any, name: str) -> Any:
    """Read a target from a ``ScanRequest`` or a raw stored ``scan_config``."""
    return body.get(name) if isinstance(body, dict) else getattr(body, name, None)


def uses_ambient_scan_targets(body: Any) -> bool:
    return bool(_field(body, "k8s") or _field(body, "connectors"))


def ambient_scan_refusal(body: Any, tenant_id: str) -> str | None:
    """Why a scan request may not use ambient targets now (``None`` when it may)."""
    if not uses_ambient_scan_targets(body):
        return None
    if not ambient_tenant_permitted(tenant_id):
        return TENANT_NOT_PERMITTED_NOTE
    if _field(body, "k8s") and not api_k8s_scans_enabled():
        return ambient_disabled_note(API_K8S_SCANS_ENV, K8S_SURFACE)
    if _field(body, "connectors") and not api_connector_scans_enabled():
        return ambient_disabled_note(API_CONNECTOR_SCANS_ENV, CONNECTOR_SURFACE)
    return None


def require_ambient_scan_targets(body: Any, *, tenant_id: str, ambient_caller: bool) -> None:
    """Refuse a scan request that reaches ambient targets without opt-in and permission."""
    if not uses_ambient_scan_targets(body):
        return
    if not ambient_caller:
        raise HTTPException(status_code=403, detail=ADMIN_ONLY_NOTE)
    refusal = ambient_scan_refusal(body, tenant_id)
    if refusal:
        raise HTTPException(status_code=403, detail=refusal)


def connector_health_refusal(request: Request) -> str | None:
    """Why this caller may not probe a SaaS connector with the server's tokens."""
    if not caller_may_use_ambient(request):
        return ADMIN_ONLY_NOTE
    if not api_connector_scans_enabled():
        return ambient_disabled_note(API_CONNECTOR_SCANS_ENV, CONNECTOR_SURFACE)
    return None


def require_connector_health_caller(request: Request) -> None:
    refusal = connector_health_refusal(request)
    if refusal:
        raise HTTPException(status_code=403, detail=refusal)


def discover_idp_subjects(request: Request) -> list[dict[str, object]]:
    """Okta/Entra non-human identities, read with the API server's own IdP tokens.

    Reference-only (never secret material); each provider gates on its own
    ``*_DISCOVERY`` flag, and only the tenant bound to these credentials may ask.
    """
    if not ambient_tenant_permitted(_request_tenant(request)):
        raise HTTPException(status_code=403, detail=TENANT_NOT_PERMITTED_NOTE)
    from agent_bom.graph.nhi_overlay import merge_discovery_results
    from agent_bom.identity import discover_entra_non_human_identities, discover_okta_non_human_identities

    merged = merge_discovery_results([discover_okta_non_human_identities(), discover_entra_non_human_identities()])
    return list(merged.get("identities", []))
