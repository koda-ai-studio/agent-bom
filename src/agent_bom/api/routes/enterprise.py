"""Enterprise API routes — auth, audit, exceptions, baselines, trends, SIEM, Jira, FP.

Endpoints:
    POST   /v1/auth/dev-session              bootstrap loopback dev browser session
    POST   /v1/auth/invitations              create a new tenant + mint its first scoped key (admin)
    POST   /v1/auth/keys                      create API key
    POST   /v1/auth/keys/{key_id}/rotate      rotate API key
    GET    /v1/auth/keys                      list API keys
    DELETE /v1/auth/keys/{key_id}             revoke API key
    GET    /v1/auth/saml/metadata             generate SP metadata for IdP setup
    POST   /v1/auth/saml/relay-state          issue one-time RelayState nonce
    POST   /v1/auth/saml/login                verify a SAML assertion and mint a short-lived API key
    GET    /v1/audit                          audit log entries
    GET    /v1/audit/integrity                verify audit HMAC integrity
    GET    /v1/audit/export                   export audit evidence packet
    POST   /v1/audit/export/verify            verify a signed audit export packet
    POST   /v1/exceptions                     create vuln exception
    GET    /v1/exceptions                     list exceptions
    GET    /v1/exceptions/{exception_id}      get exception
    PUT    /v1/exceptions/{exception_id}/approve  approve exception
    PUT    /v1/exceptions/{exception_id}/revoke   revoke exception
    DELETE /v1/exceptions/{exception_id}      delete exception
    POST   /v1/baseline/compare               compare two scan results
    GET    /v1/trends                         historical trend data
    GET    /v1/siem/connectors                list SIEM connector types
    POST   /v1/siem/test                      test SIEM connectivity
    POST   /v1/findings/false-positive        mark finding as false positive
    GET    /v1/findings/false-positives        list false positive entries
    DELETE /v1/findings/false-positive/{id}   un-mark false positive
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from agent_bom.api.finding_scope_filters import normalize_export_filters
from agent_bom.api.models import FalsePositiveRequest as FalsePositiveRequest
from agent_bom.api.models import FindingClass, FindingTriageVexIngestRequest
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.enterprise import AuthPolicyResponse, FindingTriageVexResponse
from agent_bom.api.routes.enterprise_routes import findings, governance, keys, sessions, sso, trials
from agent_bom.api.routes.enterprise_routes._models import _FEEDBACK_PREFIX as _FEEDBACK_PREFIX
from agent_bom.api.routes.enterprise_routes._models import _LEGACY_FALSE_POSITIVE_PREFIX as _LEGACY_FALSE_POSITIVE_PREFIX
from agent_bom.api.routes.enterprise_routes._models import _TRIAGE_PREFIX as _TRIAGE_PREFIX
from agent_bom.api.routes.enterprise_routes._models import AuditExportVerifyRequest as AuditExportVerifyRequest
from agent_bom.api.routes.enterprise_routes._models import BrowserSessionRequest as BrowserSessionRequest
from agent_bom.api.routes.enterprise_routes._models import ManagedTrialInvitationRequest as ManagedTrialInvitationRequest
from agent_bom.api.routes.enterprise_routes._models import ManagedTrialOIDCStartRequest as ManagedTrialOIDCStartRequest
from agent_bom.api.routes.enterprise_routes._models import TriageOwnerIndex as TriageOwnerIndex
from agent_bom.api.routes.enterprise_routes._models import TriageOwnerKey as TriageOwnerKey
from agent_bom.api.routes.enterprise_routes._models import TriageStateIndex as TriageStateIndex
from agent_bom.api.routes.enterprise_routes._models import _feedback_reason as _feedback_reason
from agent_bom.api.routes.enterprise_routes._models import _feedback_response as _feedback_response
from agent_bom.api.routes.enterprise_routes._models import _parse_feedback_reason as _parse_feedback_reason
from agent_bom.api.routes.enterprise_routes._models import _parse_triage_reason as _parse_triage_reason
from agent_bom.api.routes.enterprise_routes._models import _request_actor as _request_actor
from agent_bom.api.routes.enterprise_routes._models import _triage_reason as _triage_reason
from agent_bom.api.routes.enterprise_routes._models import _triage_response as _triage_response
from agent_bom.api.routes.enterprise_routes._models import _validate_triage_decision as _validate_triage_decision
from agent_bom.api.routes.enterprise_routes._session_helpers import (
    _auth_session_client_identity_posture as _auth_session_client_identity_posture,
)
from agent_bom.api.routes.enterprise_routes._session_helpers import _auth_session_limit as _auth_session_limit
from agent_bom.api.routes.enterprise_routes._session_helpers import _auth_session_state as _auth_session_state
from agent_bom.api.routes.enterprise_routes._session_helpers import _check_auth_session_rate_limit as _check_auth_session_rate_limit
from agent_bom.api.routes.enterprise_routes._session_helpers import _clear_browser_session_cookie as _clear_browser_session_cookie
from agent_bom.api.routes.enterprise_routes._session_helpers import _client_fingerprint as _client_fingerprint
from agent_bom.api.routes.enterprise_routes._session_helpers import _consume_saml_relay_state as _consume_saml_relay_state
from agent_bom.api.routes.enterprise_routes._session_helpers import _consume_saml_response_once as _consume_saml_response_once
from agent_bom.api.routes.enterprise_routes._session_helpers import _delete_browser_session_cookies as _delete_browser_session_cookies
from agent_bom.api.routes.enterprise_routes._session_helpers import _loopback_browser_origin as _loopback_browser_origin
from agent_bom.api.routes.enterprise_routes._session_helpers import _new_saml_relay_state as _new_saml_relay_state
from agent_bom.api.routes.enterprise_routes._session_helpers import _relay_state_digest as _relay_state_digest
from agent_bom.api.routes.enterprise_routes._session_helpers import _saml_idp_initiated_allowed as _saml_idp_initiated_allowed
from agent_bom.api.routes.enterprise_routes._session_helpers import _saml_relay_nonce as _saml_relay_nonce
from agent_bom.api.routes.enterprise_routes._session_helpers import _saml_relay_ttl_seconds as _saml_relay_ttl_seconds
from agent_bom.api.routes.enterprise_routes._session_helpers import _saml_response_digest as _saml_response_digest
from agent_bom.api.routes.enterprise_routes._session_helpers import _session_cookie_max_age as _session_cookie_max_age
from agent_bom.api.routes.enterprise_routes._session_helpers import _session_cookie_secure as _session_cookie_secure
from agent_bom.api.routes.enterprise_routes._session_helpers import _set_browser_session_cookie as _set_browser_session_cookie
from agent_bom.api.routes.enterprise_routes.findings import build_tenant_triage_owner_index as build_tenant_triage_owner_index
from agent_bom.api.routes.enterprise_routes.findings import build_tenant_triage_state_index as build_tenant_triage_state_index
from agent_bom.api.routes.enterprise_routes.findings import create_finding_feedback as create_finding_feedback
from agent_bom.api.routes.enterprise_routes.findings import create_finding_triage as create_finding_triage
from agent_bom.api.routes.enterprise_routes.findings import list_false_positives as list_false_positives
from agent_bom.api.routes.enterprise_routes.findings import list_finding_feedback as list_finding_feedback
from agent_bom.api.routes.enterprise_routes.findings import list_finding_triage as list_finding_triage
from agent_bom.api.routes.enterprise_routes.findings import mark_false_positive as mark_false_positive
from agent_bom.api.routes.enterprise_routes.findings import record_finding_triage as record_finding_triage
from agent_bom.api.routes.enterprise_routes.findings import remove_false_positive as remove_false_positive
from agent_bom.api.routes.enterprise_routes.findings import remove_finding_feedback as remove_finding_feedback
from agent_bom.api.routes.enterprise_routes.findings import triage_owner_for as triage_owner_for
from agent_bom.api.routes.enterprise_routes.findings import triage_state_for as triage_state_for
from agent_bom.api.routes.enterprise_routes.findings import update_finding_triage_decision as update_finding_triage_decision
from agent_bom.api.routes.enterprise_routes.governance import _configured_runtime_audit_log_path as _configured_runtime_audit_log_path
from agent_bom.api.routes.enterprise_routes.governance import approve_exception as approve_exception
from agent_bom.api.routes.enterprise_routes.governance import audit_integrity as audit_integrity
from agent_bom.api.routes.enterprise_routes.governance import compare_baseline as compare_baseline
from agent_bom.api.routes.enterprise_routes.governance import create_exception as create_exception
from agent_bom.api.routes.enterprise_routes.governance import delete_exception as delete_exception
from agent_bom.api.routes.enterprise_routes.governance import export_audit_entries as export_audit_entries
from agent_bom.api.routes.enterprise_routes.governance import get_exception as get_exception
from agent_bom.api.routes.enterprise_routes.governance import get_trends as get_trends
from agent_bom.api.routes.enterprise_routes.governance import list_audit_entries as list_audit_entries
from agent_bom.api.routes.enterprise_routes.governance import list_exceptions as list_exceptions
from agent_bom.api.routes.enterprise_routes.governance import list_siem_connectors as list_siem_connectors
from agent_bom.api.routes.enterprise_routes.governance import revoke_exception as revoke_exception
from agent_bom.api.routes.enterprise_routes.governance import test_siem_connection as test_siem_connection
from agent_bom.api.routes.enterprise_routes.governance import update_issue_mapping_status as update_issue_mapping_status
from agent_bom.api.routes.enterprise_routes.governance import verify_audit_export as verify_audit_export
from agent_bom.api.routes.enterprise_routes.keys import create_browser_session as create_browser_session
from agent_bom.api.routes.enterprise_routes.keys import create_key as create_key
from agent_bom.api.routes.enterprise_routes.keys import create_loopback_dev_session as create_loopback_dev_session
from agent_bom.api.routes.enterprise_routes.keys import delete_browser_session as delete_browser_session
from agent_bom.api.routes.enterprise_routes.keys import list_keys as list_keys
from agent_bom.api.routes.enterprise_routes.keys import rotate_key as rotate_key
from agent_bom.api.routes.enterprise_routes.sessions import _allowed_post_login_path as _allowed_post_login_path
from agent_bom.api.routes.enterprise_routes.sessions import _consume_oidc_login_state as _consume_oidc_login_state
from agent_bom.api.routes.enterprise_routes.sessions import _new_oidc_login_state as _new_oidc_login_state
from agent_bom.api.routes.enterprise_routes.sessions import _oidc_login_nonce as _oidc_login_nonce
from agent_bom.api.routes.enterprise_routes.sessions import _safe_post_login_path as _safe_post_login_path
from agent_bom.api.routes.enterprise_routes.sessions import auth_debug as auth_debug
from agent_bom.api.routes.enterprise_routes.sessions import auth_me as auth_me
from agent_bom.api.routes.enterprise_routes.sessions import delete_key as delete_key
from agent_bom.api.routes.enterprise_routes.sessions import managed_trial_oidc_start as managed_trial_oidc_start
from agent_bom.api.routes.enterprise_routes.sessions import managed_trial_oidc_start_form as managed_trial_oidc_start_form
from agent_bom.api.routes.enterprise_routes.sessions import oidc_browser_login as oidc_browser_login
from agent_bom.api.routes.enterprise_routes.sso import _consume_snowflake_login_state as _consume_snowflake_login_state
from agent_bom.api.routes.enterprise_routes.sso import _new_snowflake_login_state as _new_snowflake_login_state
from agent_bom.api.routes.enterprise_routes.sso import _snowflake_login_nonce as _snowflake_login_nonce
from agent_bom.api.routes.enterprise_routes.sso import saml_login as saml_login
from agent_bom.api.routes.enterprise_routes.sso import saml_metadata as saml_metadata
from agent_bom.api.routes.enterprise_routes.sso import saml_relay_state as saml_relay_state
from agent_bom.api.routes.enterprise_routes.sso import snowflake_oauth_callback as snowflake_oauth_callback
from agent_bom.api.routes.enterprise_routes.sso import snowflake_oauth_login as snowflake_oauth_login
from agent_bom.api.routes.enterprise_routes.trials import _discover_nhi_credentials as _discover_nhi_credentials
from agent_bom.api.routes.enterprise_routes.trials import _hosted_invite_url as _hosted_invite_url
from agent_bom.api.routes.enterprise_routes.trials import _new_invited_tenant_id as _new_invited_tenant_id
from agent_bom.api.routes.enterprise_routes.trials import _require_managed_trial_operator as _require_managed_trial_operator
from agent_bom.api.routes.enterprise_routes.trials import _slugify_org as _slugify_org
from agent_bom.api.routes.enterprise_routes.trials import _transition_managed_trial_tenant as _transition_managed_trial_tenant
from agent_bom.api.routes.enterprise_routes.trials import _trial_lifecycle_payload as _trial_lifecycle_payload
from agent_bom.api.routes.enterprise_routes.trials import auth_quota as auth_quota
from agent_bom.api.routes.enterprise_routes.trials import auth_scim_config as auth_scim_config
from agent_bom.api.routes.enterprise_routes.trials import auth_scopes as auth_scopes
from agent_bom.api.routes.enterprise_routes.trials import auth_secret_credential_expiry as auth_secret_credential_expiry
from agent_bom.api.routes.enterprise_routes.trials import auth_secret_lifecycle as auth_secret_lifecycle
from agent_bom.api.routes.enterprise_routes.trials import auth_secret_rotation_plan as auth_secret_rotation_plan
from agent_bom.api.routes.enterprise_routes.trials import create_invitation as create_invitation
from agent_bom.api.routes.enterprise_routes.trials import create_managed_trial_invitation as create_managed_trial_invitation
from agent_bom.api.routes.enterprise_routes.trials import get_managed_trial_tenant as get_managed_trial_tenant
from agent_bom.api.routes.enterprise_routes.trials import reset_auth_quota as reset_auth_quota
from agent_bom.api.routes.enterprise_routes.trials import resume_managed_trial_tenant as resume_managed_trial_tenant
from agent_bom.api.routes.enterprise_routes.trials import retry_managed_trial_tenant_cleanup as retry_managed_trial_tenant_cleanup
from agent_bom.api.routes.enterprise_routes.trials import revoke_managed_trial_tenant as revoke_managed_trial_tenant
from agent_bom.api.routes.enterprise_routes.trials import suspend_managed_trial_tenant as suspend_managed_trial_tenant
from agent_bom.api.routes.enterprise_routes.trials import update_auth_quota as update_auth_quota
from agent_bom.api.stores import _get_exception_store
from agent_bom.api.stores import _get_issue_mapping_store as _get_issue_mapping_store
from agent_bom.api.stores import _get_store as _get_store
from agent_bom.api.stores import _get_trend_store as _get_trend_store
from agent_bom.api.suppression_approval import reset_suppression_request, suppression_active
from agent_bom.api.tenancy import require_body_tenant_match as require_body_tenant_match
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.security import sanitize_error, sanitize_text

router = APIRouter()
_logger = logging.getLogger(__name__)

router.include_router(keys.router)


@router.get("/auth/policy", **documented(AuthPolicyResponse), tags=["enterprise"])
def auth_policy(request: Request) -> dict:
    """Report control-plane operator posture for auth, rate-limit and runtime safety controls.

    Intended for operator runbooks and posture dashboards. The payload is the
    process-wide control-plane configuration (rotation policy, header gates,
    sandbox defaults, identity provisioning posture) — it is not a tenant-scoped
    record. The only tenant-scoped fields are ``tenant_quota_runtime`` (the
    effective quotas for the calling tenant) and the resolved tenant id used to
    derive them; everything else describes the deployment as a whole.
    """
    from agent_bom.api.audit_log import describe_audit_hmac_status
    from agent_bom.api.auth import get_api_key_policy
    from agent_bom.api.auth_posture import get_auth_posture, get_auth_runtime_status, get_trusted_proxy_auth_status
    from agent_bom.api.compliance_signing import describe_signing_posture
    from agent_bom.api.middleware import (
        describe_proxy_control_plane_mtls_posture,
        describe_security_header_posture,
        get_rate_limit_key_status,
        get_rate_limit_runtime_status,
    )
    from agent_bom.api.oidc import describe_oidc_posture
    from agent_bom.api.saml import describe_saml_posture
    from agent_bom.api.scim import describe_scim_posture
    from agent_bom.api.secret_lifecycle import describe_secret_lifecycle_posture
    from agent_bom.api.shared_auth_state import auth_state_posture
    from agent_bom.api.storage_schema import describe_control_plane_storage_schema
    from agent_bom.api.tenant_quota import default_tenant_quotas, get_tenant_quota_runtime
    from agent_bom.backpressure import describe_backpressure_posture
    from agent_bom.data_boundaries import describe_data_access_boundaries
    from agent_bom.proxy_sandbox import describe_proxy_sandbox_posture

    api_policy = get_api_key_policy()
    rl_status = get_rate_limit_key_status()
    rl_runtime = get_rate_limit_runtime_status()
    auth_runtime = get_auth_runtime_status()
    tenant_id = require_request_tenant_id(request)
    defaults = default_tenant_quotas()
    return {
        "api_key": {
            "default_ttl_seconds": api_policy.default_ttl_seconds,
            "max_ttl_seconds": api_policy.max_ttl_seconds,
            "default_overlap_seconds": api_policy.default_overlap_seconds,
            "max_overlap_seconds": api_policy.max_overlap_seconds,
            "rotation_policy": "enforced",
            "rotation_endpoint": "/v1/auth/keys/{key_id}/rotate",
        },
        "rate_limit_key": rl_status,
        "audit_hmac": describe_audit_hmac_status(),
        "ui": {
            "recommended_mode": auth_runtime["recommended_ui_mode"],
            "configured_modes": auth_runtime["configured_modes"],
            "browser_session": "signed_http_only_cookie",
            "session_storage_fallback": "disabled",
            "credentials_mode": "include",
            "trusted_proxy_headers": ["X-Agent-Bom-Role", "X-Agent-Bom-Tenant-ID", "X-Agent-Bom-Proxy-Secret"],
            "trusted_proxy_secret_env": "AGENT_BOM_TRUST_PROXY_AUTH_SECRET",
            "message": (
                "Recommended browser auth is same-origin reverse-proxy OIDC with the proxy injecting trusted "
                "X-Agent-Bom-* headers plus X-Agent-Bom-Proxy-Secret attestation. For single-user local or pilot "
                "access, the UI exchanges an API key for a signed, expiring, CSRF-bound httpOnly browser session cookie "
                "without storing the key in browser storage."
            ),
        },
        "rate_limit_runtime": rl_runtime,
        "auth_session_client_identity": _auth_session_client_identity_posture(),
        "trusted_proxy_auth": get_trusted_proxy_auth_status(),
        "proxy_control_plane_mtls": describe_proxy_control_plane_mtls_posture(listener_host=get_auth_posture().listener_host),
        "security_headers": describe_security_header_posture(),
        "backpressure": describe_backpressure_posture(),
        "proxy_sandbox": describe_proxy_sandbox_posture(),
        "data_access_boundaries": describe_data_access_boundaries(),
        "auth_state_backend": auth_state_posture(),
        "secret_integrity": {
            "audit_hmac": describe_audit_hmac_status(),
            "compliance_signing": describe_signing_posture(),
        },
        "secret_lifecycle": describe_secret_lifecycle_posture(),
        "tenant_quotas": defaults,
        "tenant_quota_runtime": get_tenant_quota_runtime(tenant_id),
        "storage_schema": describe_control_plane_storage_schema(),
        "identity_provisioning": {
            "oidc": describe_oidc_posture(),
            "saml": describe_saml_posture(),
            "scim": describe_scim_posture(),
            "session_revocation": {
                "service_keys": "API key revocation takes effect immediately at the control-plane auth layer.",
                "session_api_key": (
                    "The browser fallback key is scoped to the current browser session and disappears when that local session is cleared."
                ),
                "browser_sessions": (
                    "OIDC or reverse-proxy browser sessions must be terminated at the upstream identity provider or trusted proxy."
                ),
            },
        },
    }


router.include_router(trials.router)


router.include_router(sessions.router)


@router.get("/auth/oidc/callback", tags=["enterprise"])
async def oidc_browser_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> RedirectResponse:
    """Complete OIDC auth-code + PKCE login and mint a browser session cookie."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, resolve_scim_user_role
    from agent_bom.api.managed_trial_invitation import (
        ManagedTrialInvitationConfigurationError,
        ManagedTrialInvitationError,
        get_managed_trial_invitation_store,
        managed_trial_invitations_enabled,
    )
    from agent_bom.api.oidc import OIDCError, claims_have_role_signal, claims_to_role
    from agent_bom.api.oidc_browser import (
        OIDC_PKCE_COOKIE_NAME,
        OIDCBrowserConfig,
        exchange_code_for_tokens,
        managed_trial_invitation_digest_from_pkce_cookie,
        open_pkce_cookie,
        subject_from_claims,
        verify_browser_id_token,
    )

    _check_auth_session_rate_limit(request)
    if error:
        detail = sanitize_text(error_description or error)
        raise HTTPException(status_code=401, detail=f"OIDC login failed: {detail}")
    if not code:
        raise HTTPException(status_code=401, detail="OIDC authorization code required")

    _consume_oidc_login_state(state)
    sealed = request.cookies.get(OIDC_PKCE_COOKIE_NAME, "")
    if not sealed:
        raise HTTPException(status_code=401, detail="OIDC PKCE cookie missing")

    managed_invitation = None
    managed_invitation_store = None
    managed_verified_email: str | None = None
    try:
        cfg = OIDCBrowserConfig.from_env()
        code_verifier, nonce, return_to = open_pkce_cookie(sealed)
        managed_invitation_digest = managed_trial_invitation_digest_from_pkce_cookie(sealed)
        token_payload = exchange_code_for_tokens(cfg, code=code, code_verifier=code_verifier)
        id_token = str(token_payload.get("id_token") or "").strip()
        if not id_token:
            raise OIDCError("OIDC token response missing id_token")
        claims = verify_browser_id_token(cfg, id_token, nonce=nonce)
        if managed_invitation_digest is not None:
            if not managed_trial_invitations_enabled():
                raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")
            subject = str(claims.get("sub") or "").strip()
            email = str(claims.get("email") or "").strip()
            if claims.get("email_verified") is not True or not subject or not email:
                raise ManagedTrialInvitationError("Invalid or expired managed-trial invitation")

            def _load_managed_invitation() -> tuple[Any, Any]:
                store = get_managed_trial_invitation_store()
                return store, store.get_by_digest(managed_invitation_digest)

            managed_invitation_store, managed_invitation = await anyio.to_thread.run_sync(_load_managed_invitation)
            managed_verified_email = email
            role = Role.ANALYST.value
            tenant_id = managed_invitation.tenant_id
        else:
            if cfg.oidc.require_role_claim and not claims_have_role_signal(claims, cfg.oidc.role_claim):
                raise OIDCError(f"JWT missing required role claim '{cfg.oidc.role_claim}'")
            role = claims_to_role(claims, cfg.oidc.role_claim)
            tenant_id = cfg.oidc.resolve_tenant(claims)
            subject = subject_from_claims(claims)
    except ManagedTrialInvitationConfigurationError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    except ManagedTrialInvitationError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired managed-trial invitation") from exc
    except OIDCError as exc:
        raise HTTPException(status_code=401, detail=sanitize_error(exc)) from exc

    if managed_invitation is not None:
        from agent_bom.api.managed_trial import MANAGED_TRIAL_ANALYST_SCOPES

        role_value = Role.ANALYST.value
        auth_method = "managed_trial_oidc"
        scopes = list(MANAGED_TRIAL_ANALYST_SCOPES)
    else:
        scim_resolution = resolve_scim_user_role(tenant_id, subject)
        effective_role = scim_resolution.role.value if scim_resolution.role is not None else role
        try:
            role_value = Role(effective_role).value
        except ValueError:
            role_value = Role.VIEWER.value
        auth_method = "oidc_browser"
        scopes = ["oidc-browser-session"]

    return_to = _allowed_post_login_path(return_to)
    response = RedirectResponse(url=return_to, status_code=302)
    _set_browser_session_cookie(
        response,
        request,
        subject=subject,
        role=role_value,
        tenant_id=tenant_id,
        auth_method=auth_method,
        scopes=scopes,
    )
    if managed_invitation is not None and managed_invitation_store is not None and managed_verified_email is not None:

        def _accept_managed_invitation() -> Any:
            return managed_invitation_store.accept_digest(
                managed_invitation.token_digest,
                verified_email=managed_verified_email,
                verified_subject=subject,
            )

        try:
            await anyio.to_thread.run_sync(_accept_managed_invitation)
        except ManagedTrialInvitationError as exc:
            raise HTTPException(status_code=401, detail="Invalid or expired managed-trial invitation") from exc
    secure = _session_cookie_secure(request)
    response.delete_cookie(OIDC_PKCE_COOKIE_NAME, httponly=True, secure=secure, samesite="lax", path="/")
    if managed_invitation is not None:
        try:
            log_action(
                "auth.managed_trial_invitation_accepted",
                actor=subject,
                resource=f"managed-trial-invitation/{managed_invitation.invitation_id}",
                tenant_id=tenant_id,
                details={"role": role_value, "auth_method": auth_method},
            )
        except Exception:
            _logger.warning("Managed-trial invitation acceptance audit write failed")
    else:
        log_action(
            "auth.oidc_browser_login",
            actor=subject,
            resource="auth/oidc",
            tenant_id=tenant_id,
            details={"role": role_value, "auth_method": auth_method},
        )
    return response


router.include_router(sso.router)


router.include_router(governance.router)


router.include_router(findings.router)


@router.get("/findings/triage/vex", **documented(FindingTriageVexResponse), tags=["enterprise"])
def export_finding_triage_vex(
    request: Request,
    assignee: Annotated[str | None, Query(max_length=256)] = None,
    package: Annotated[str | None, Query(max_length=256)] = None,
    vulnerability_id: Annotated[str | None, Query(max_length=128)] = None,
    server_name: Annotated[str | None, Query(max_length=256)] = None,
    view_scope: Annotated[Literal["all", "current"], Query(alias="scope")] = "all",
    q: Annotated[str | None, Query(max_length=256)] = None,
    severity: str | None = None,
    scan_id: Annotated[str | None, Query(max_length=128)] = None,
    provider: Annotated[str | None, Query(max_length=64)] = None,
    account: Annotated[str | None, Query(max_length=256)] = None,
    environment: Annotated[str | None, Query(max_length=64)] = None,
    domain: Annotated[str | None, Query(max_length=32)] = None,
    window_days: Annotated[int | None, Query(ge=0, le=3650)] = None,
    status: Annotated[str | None, Query(max_length=16)] = None,
    lane: Annotated[str | None, Query(max_length=32)] = None,
    finding_class: FindingClass | None = None,
    kev: bool | None = None,
    framework: Annotated[str | None, Query(max_length=64)] = None,
    control: Annotated[str | None, Query(max_length=64)] = None,
    owner: Annotated[str | None, Query(max_length=256)] = None,
    sla: Literal["overdue", "due", "unassigned"] | None = None,
    reachability: Literal["reachable", "unreachable", "unassessed"] | None = None,
    triage: Literal["not_affected", "affected", "under_investigation", "untriaged"] | None = None,
) -> dict:
    """Export signed OpenVEX for eligible tenant-scoped triage decisions."""
    from agent_bom.api.compliance_signing import describe_signer_disclosure, sign_compliance_bundle
    from agent_bom.api.routes.scan import current_findings_snapshot
    from agent_bom.vex import VexDocument, VexJustification, VexStatement, VexStatus, export_openvex

    tenant_id = require_request_tenant_id(request)
    triage_filters = {
        key: value.strip()
        for key, value in {
            "assignee": assignee,
            "package": package,
            "vulnerability_id": vulnerability_id,
            "server_name": server_name,
        }.items()
        if value is not None and value.strip()
    }
    finding_filter_values: dict[str, Any] = {
        "q": q,
        "severity": severity,
        "scan_id": scan_id,
        "provider": provider,
        "account": account,
        "environment": environment,
        "domain": domain,
        "window_days": window_days,
        "status": status,
        "lane": lane,
        "finding_class": getattr(finding_class, "value", finding_class),
        "kev": kev,
        "framework": framework,
        "control": control,
        "owner": owner,
        "sla": sla,
        "reachability": reachability,
        "triage": triage,
    }
    finding_filters = normalize_export_filters(finding_filter_values)
    active_filters = dict(triage_filters)
    if view_scope == "current":
        active_filters["scope"] = view_scope
    active_filters.update({key: str(value).lower() if isinstance(value, bool) else str(value) for key, value in finding_filters.items()})
    scoped_findings: list[dict[str, Any]] | None = None
    finding_scope: dict[str, Any] | None = None
    if view_scope == "current":
        snapshot = current_findings_snapshot(request, **finding_filters)
        scoped_findings = [row for row in snapshot.get("findings", []) if isinstance(row, dict)]
        raw_completeness = snapshot.get("completeness")
        finding_scope = {
            "count": len(scoped_findings),
            "total": snapshot.get("total"),
            "warnings": list(snapshot.get("warnings", [])),
            "completeness": dict(raw_completeness) if isinstance(raw_completeness, dict) else {},
        }

    def _scope_matches(exc: Any) -> bool:
        if scoped_findings is None:
            return True

        def _matches(pattern: str, values: set[str], *, empty_matches_empty: bool = False) -> bool:
            normalized = pattern.strip().lower()
            if normalized == "*":
                return True
            if not normalized and empty_matches_empty:
                return "" in values
            return normalized in values

        for finding in scoped_findings:
            raw_asset = finding.get("asset")
            asset = raw_asset if isinstance(raw_asset, dict) else {}
            raw_evidence = finding.get("evidence")
            evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
            vuln_values = {
                str(value).strip().lower()
                for value in (
                    finding.get("vulnerability_id"),
                    finding.get("cve_id"),
                    finding.get("advisory_id"),
                )
                if str(value or "").strip()
            }
            package_values = {
                str(value).strip().lower()
                for value in (
                    finding.get("package"),
                    finding.get("package_name"),
                    evidence.get("package_name"),
                    asset.get("purl"),
                    asset.get("name"),
                    asset.get("identifier"),
                )
                if str(value or "").strip()
            }
            raw_servers = finding.get("affected_servers")
            server_values = {
                str(value).strip().lower() for value in (raw_servers if isinstance(raw_servers, list) else []) if str(value or "").strip()
            }
            server_values.add(str(finding.get("server_name") or "").strip().lower())
            if (
                _matches(str(exc.vuln_id), vuln_values)
                and _matches(str(exc.package_name), package_values)
                and _matches(str(exc.server_name), server_values, empty_matches_empty=True)
            ):
                return True
        return False

    statements = []
    for exc in _get_exception_store().list_all(tenant_id=tenant_id):
        data = _parse_triage_reason(exc.reason)
        if data is None:
            continue
        if not suppression_active(exc) or data.get("decision") != "not_affected" or not data.get("justification"):
            continue
        if (
            "assignee" in triage_filters
            and str(data.get("assignee") or exc.approved_by or "").strip().lower() != triage_filters["assignee"].lower()
        ):
            continue
        if "package" in triage_filters and str(exc.package_name).strip().lower() != triage_filters["package"].lower():
            continue
        if "vulnerability_id" in triage_filters and str(exc.vuln_id).strip().lower() != triage_filters["vulnerability_id"].lower():
            continue
        if "server_name" in triage_filters and str(exc.server_name).strip().lower() != triage_filters["server_name"].lower():
            continue
        if not _scope_matches(exc):
            continue
        statements.append(
            VexStatement(
                vulnerability_id=exc.vuln_id,
                status=VexStatus.NOT_AFFECTED,
                justification=VexJustification(str(data["justification"])),
                impact_statement=str(data.get("decision_reason") or ""),
                products=[] if exc.package_name in {"", "*"} else [exc.package_name],
                timestamp=str(data.get("reviewed_at") or exc.approved_at or exc.created_at),
                author=str(data.get("assignee") or exc.approved_by or exc.requested_by or "agent-bom"),
            )
        )
    doc = VexDocument(
        statements=statements,
        metadata={
            "id": f"urn:agent-bom:vex:{tenant_id}:{len(statements)}",
            "author": "agent-bom",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
        },
    )
    payload = export_openvex(doc)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = sign_compliance_bundle(canonical)
    return {
        "schema_version": "findings.triage.vex.v1",
        "tenant_id": tenant_id,
        "count": len(statements),
        "format": "openvex",
        "filters": active_filters,
        **({"finding_scope": finding_scope} if finding_scope is not None else {}),
        "vex": payload,
        "signature": {
            "algorithm": signature.algorithm,
            "signature_hex": signature.signature_hex,
            "key_id": signature.key_id,
            # Same disclosure contract as the compliance evidence bundle: an
            # algorithm name alone hides that the default deployment signs
            # with a per-process key nobody can verify against.
            **describe_signer_disclosure().as_bundle_field(),
        },
    }


@router.post("/findings/triage/vex/ingest", tags=["enterprise"], status_code=201)
def ingest_finding_triage_vex(request: Request, req: FindingTriageVexIngestRequest) -> dict:
    """Ingest an OpenVEX document and apply its statements as triage suppressions.

    ``not_affected`` statements become tenant-scoped triage decisions (round-tripping
    with :func:`export_finding_triage_vex`); ``fixed`` statements are recorded as
    ``fixed_verified`` suppressions. ``affected`` / ``under_investigation`` statements
    carry no suppression and are skipped. Re-ingesting the same document updates the
    matching entries in place (idempotent by vulnerability + product)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus, VulnException
    from agent_bom.vex import VexStatus, parse_vex

    tenant_id = require_request_tenant_id(request)
    actor = _request_actor(request)
    try:
        doc = parse_vex(req.vex)
    except ValueError as parse_err:
        raise HTTPException(status_code=400, detail=f"Invalid VEX document: {sanitize_error(str(parse_err))}") from parse_err

    store = _get_exception_store()
    # Index existing tenant exceptions by (vuln_id, package) so re-ingest updates
    # in place rather than accumulating duplicates.
    existing: dict[tuple[str, str], Any] = {}
    for exc in store.list_all(tenant_id=tenant_id):
        if exc.status == ExceptionStatus.PENDING and not exc.approved_by:
            existing[(exc.vuln_id, exc.package_name)] = exc

    now = datetime.now(timezone.utc).isoformat()
    applied = 0
    skipped: list[dict[str, str]] = []

    for stmt in doc.statements:
        if not stmt.vulnerability_id:
            continue
        products = stmt.products or [""]
        for product in products:
            package = product or "*"
            if stmt.status == VexStatus.NOT_AFFECTED:
                if stmt.justification is None:
                    skipped.append({"vulnerability_id": stmt.vulnerability_id, "reason": "missing_justification"})
                    continue
                reason = _triage_reason(
                    {
                        "queue_state": "decided",
                        "decision": "not_affected",
                        "justification": stmt.justification.value,
                        "decision_reason": stmt.impact_statement or stmt.action_statement or "",
                        "assignee": stmt.author or "",
                        "reviewed_at": now,
                        "source": "vex_ingest",
                    }
                )
            elif stmt.status == VexStatus.FIXED:
                reason = _feedback_reason("fixed_verified", stmt.impact_statement or stmt.action_statement or "")
            else:
                skipped.append({"vulnerability_id": stmt.vulnerability_id, "reason": f"status_{stmt.status.value}"})
                continue

            exc = existing.get((stmt.vulnerability_id, package))
            if exc is None:
                exc = VulnException(
                    vuln_id=stmt.vulnerability_id,
                    package_name=package,
                    reason=reason,
                    requested_by=actor,
                    status=ExceptionStatus.PENDING,
                    tenant_id=tenant_id,
                )
                existing[(stmt.vulnerability_id, package)] = exc
            else:
                exc.reason = reason
            reset_suppression_request(exc, decided_by=actor)
            store.put(exc, tenant_id=tenant_id)
            applied += 1

    log_action(
        "findings.triage_vex_ingested",
        actor=actor,
        resource=f"finding-triage/vex/{tenant_id}",
        tenant_id=tenant_id,
        applied=applied,
        skipped=len(skipped),
    )
    return {
        "schema_version": "findings.triage.vex-ingest.v1",
        "tenant_id": tenant_id,
        "statements": len(doc.statements),
        "applied": applied,
        "skipped": skipped,
    }


router.include_router(findings.tail_router)
