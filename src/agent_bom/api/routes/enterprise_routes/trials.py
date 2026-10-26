"""Auth scope, secret, SCIM and quota posture routes plus tenant invitation and managed-trial lifecycle routes."""

from __future__ import annotations

import logging
import re
import secrets
from typing import Any

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.models import InvitationRequest, TenantQuotaUpdateRequest
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.enterprise import (
    AuthScopesResponse,
    CredentialExpiryResponse,
    ManagedTrialTenantResponse,
    ScimConfigResponse,
    SecretLifecycleResponse,
    SecretRotationPlanResponse,
    TenantQuotaRuntimeResponse,
)
from agent_bom.api.routes.enterprise_routes._models import ManagedTrialInvitationRequest, _request_actor
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger("agent_bom.api.routes.enterprise")


@router.get("/auth/scopes", **documented(AuthScopesResponse), tags=["enterprise"])
def auth_scopes() -> dict:
    """Return the enforced RBAC scope catalog for operator tooling."""
    from agent_bom.api.middleware import APIKeyMiddleware

    scopes = APIKeyMiddleware.scope_catalog()
    return {
        "schema_version": "v1",
        "count": len(scopes),
        "wildcard_examples": ["*", "auth.*", "auth.keys:*"],
        "scopes": scopes,
    }


@router.get("/auth/secrets/lifecycle", **documented(SecretLifecycleResponse), tags=["enterprise"])
def auth_secret_lifecycle() -> dict:
    """Return non-secret lifecycle posture for configured control-plane secrets."""
    from agent_bom.api.secret_lifecycle import describe_secret_lifecycle_posture

    return describe_secret_lifecycle_posture()


@router.get("/auth/secrets/rotation-plan", **documented(SecretRotationPlanResponse), tags=["enterprise"])
def auth_secret_rotation_plan() -> dict:
    """Return a non-secret operator plan for rotating control-plane secrets."""
    from agent_bom.api.secret_lifecycle import build_secret_rotation_plan

    return build_secret_rotation_plan()


@router.get("/auth/secrets/credential-expiry", **documented(CredentialExpiryResponse), tags=["enterprise"])
def auth_secret_credential_expiry() -> dict:
    """Return non-secret credential expiry/rotation governance.

    Folds in any discovered non-human-identity (NHI) credentials so an
    operator's expiring Okta/Entra service-app / service-principal secrets are
    governed alongside control-plane secrets. NHI discovery is gated by its own
    ``*_DISCOVERY`` env flags and is a no-op (no network) when they are off, so
    this stays control-plane-only by default.
    """
    from agent_bom.api.credential_expiry import describe_credential_expiry_posture

    discovered = _discover_nhi_credentials()
    return describe_credential_expiry_posture(discovered or None)


def _discover_nhi_credentials() -> list[dict]:
    """Run gated NHI discovery and return reference-only credential records.

    Each record carries ``{id, name, credential_expires_at}`` for the expiry
    classifier — never secret material. Both providers self-gate on their
    ``*_DISCOVERY`` flag, so this returns an empty list (and makes no network
    call) when discovery is disabled. Never raises into the request path.
    """
    try:
        from agent_bom.graph.nhi_overlay import merge_discovery_results
        from agent_bom.identity import (
            discover_entra_non_human_identities,
            discover_okta_non_human_identities,
        )

        merged = merge_discovery_results([discover_okta_non_human_identities(), discover_entra_non_human_identities()])
        records: list[dict] = []
        for identity in merged.get("identities", []):
            if not isinstance(identity, dict):
                continue
            if not identity.get("credential_expires_at"):
                continue
            records.append(
                {
                    "id": identity.get("identity_id"),
                    "name": identity.get("name"),
                    "credential_expires_at": identity.get("credential_expires_at"),
                    "last_rotated": identity.get("last_rotated"),
                }
            )
        return records
    except Exception:  # noqa: BLE001 — credential-expiry posture must never fail on discovery
        return []


@router.get("/auth/scim/config", **documented(ScimConfigResponse), tags=["enterprise"])
def auth_scim_config() -> dict:
    """Return the operator-facing SCIM configuration posture."""
    from agent_bom.api.scim import describe_scim_posture

    return describe_scim_posture()


@router.get("/auth/quota", **documented(TenantQuotaRuntimeResponse), tags=["enterprise"])
def auth_quota(request: Request) -> dict:
    """Return the effective tenant quota runtime surface for the current tenant."""
    from agent_bom.api.tenant_quota import get_tenant_quota_runtime

    tenant_id = require_request_tenant_id(request)
    return get_tenant_quota_runtime(tenant_id)


@router.put("/auth/quota", tags=["enterprise"])
def update_auth_quota(request: Request, req: TenantQuotaUpdateRequest) -> dict:
    """Update tenant-specific quota overrides for the current tenant."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.tenant_quota import (
        QUOTA_NAMES,
        get_tenant_quota_overrides,
        get_tenant_quota_runtime,
        set_tenant_quota_overrides,
    )

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    updates = {name: getattr(req, name) for name in QUOTA_NAMES if name in req.model_fields_set}
    if not updates:
        raise HTTPException(status_code=400, detail="Provide at least one quota field to update.")

    previous = get_tenant_quota_overrides(tenant_id)
    current = set_tenant_quota_overrides(tenant_id, updates)
    log_action(
        "tenant.quota_updated",
        actor=actor,
        resource=f"tenant/{tenant_id}",
        tenant_id=tenant_id,
        previous_overrides=previous,
        current_overrides=current,
        updated_fields=sorted(updates),
    )
    return get_tenant_quota_runtime(tenant_id)


@router.delete("/auth/quota", tags=["enterprise"], status_code=204)
def reset_auth_quota(request: Request) -> None:
    """Clear all tenant-specific quota overrides for the current tenant."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.tenant_quota import clear_tenant_quota_overrides, get_tenant_quota_overrides

    tenant_id = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    previous = get_tenant_quota_overrides(tenant_id)
    clear_tenant_quota_overrides(tenant_id)
    log_action(
        "tenant.quota_reset",
        actor=actor,
        resource=f"tenant/{tenant_id}",
        tenant_id=tenant_id,
        previous_overrides=previous,
    )


def _slugify_org(organization: str | None) -> str:
    """Return a short, url-safe slug for a human org name (empty when unusable)."""
    if not organization:
        return ""
    slug = re.sub(r"[^a-z0-9]+", "-", organization.lower()).strip("-")
    return slug[:32].strip("-")


def _new_invited_tenant_id(organization: str | None) -> str:
    """Mint a fresh, non-colliding tenant id for an invited account.

    The id is ALWAYS server-generated with random entropy so an invite can
    never target — or leak into — an existing tenant. The optional org slug is
    a readability prefix only; the random suffix guarantees uniqueness.
    """
    from agent_bom.platform_invariants import validate_customer_tenant_id

    slug = _slugify_org(organization)
    suffix = secrets.token_hex(6)
    candidate = f"{slug}-{suffix}" if slug else f"tenant-{suffix}"
    # Random suffix means this can't be reserved; validate defensively anyway.
    return validate_customer_tenant_id(candidate)


def _hosted_invite_url(tenant_id: str) -> str | None:
    """Build the opt-in hosted sign-in link. Never embeds the raw key.

    Returns None unless ``AGENT_BOM_HOSTED_INVITE_BASE_URL`` is configured, so
    we never fabricate a link for a deployment that has no hosted front door.
    """
    base = (env_raw("AGENT_BOM_HOSTED_INVITE_BASE_URL") or "").strip()
    if not base:
        return None
    from urllib.parse import quote

    return f"{base.rstrip('/')}/login?tenant={quote(tenant_id, safe='')}"


@router.post("/auth/invitations", tags=["enterprise"], status_code=201)
def create_invitation(request: Request, req: InvitationRequest) -> dict:
    """Provision a NEW tenant and mint its first scoped API key (platform operator only).

    The hosted self-serve replacement for ``scripts/deploy/mint_hosted_admin_key.py``:
    it creates a brand-new tenant (server-generated id — an invite can never
    target an existing tenant), mints one scoped API key for it through the
    same key-minting path every other route uses (no new crypto), and returns
    a one-time invite payload. The new tenant is bounded by the conservative
    default tenant quotas automatically (they apply to any tenant with no
    overrides); the effective bounds are echoed back for operator visibility.

    Requires the platform-operator tenant, authenticated admin role and a
    delegation scope ceiling that permits a wildcard key. Authorization is
    audited in both tenants before provisioning; failed audit writes fail closed.
    The raw key is returned once and is never included in audit evidence.
    """
    from agent_bom.api.auth import Role, create_api_key, key_durability_fields
    from agent_bom.api.invitation_provisioning import provision_invited_key, require_invitation_delegation
    from agent_bom.api.tenant_quota import default_tenant_quotas

    _require_managed_trial_operator(request)
    require_invitation_delegation(request)
    try:
        role = Role(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}. Must be admin, analyst, or viewer") from None

    tenant_id = _new_invited_tenant_id(req.organization)
    key_name = _slugify_org(req.organization) or "invited"
    try:
        raw_key, api_key = create_api_key(
            name=f"{key_name}-owner",
            role=role,
            expires_at=req.expires_at,
            scopes=["*"],
            tenant_id=tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    provision_invited_key(request, api_key, team_name=(req.organization or "").strip() or tenant_id)
    quota = default_tenant_quotas()

    return {
        "raw_key": raw_key,
        "key_id": api_key.key_id,
        "key_prefix": api_key.key_prefix,
        "tenant_id": tenant_id,
        "role": api_key.role.value,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "quota": quota,
        "invite_url": _hosted_invite_url(tenant_id),
        "message": ("Store the raw_key securely and deliver it to the invited admin over a trusted channel — it will not be shown again."),
        **key_durability_fields(),
    }


@router.post("/auth/trial-invitations", tags=["enterprise"], status_code=201)
async def create_managed_trial_invitation(request: Request, req: ManagedTrialInvitationRequest) -> dict[str, Any]:
    """Create an email-bound managed-trial invitation without minting an API key.

    This operator-only surface is opt-in and PostgreSQL-only in deployed use.
    The raw token is returned once for a separate delivery adapter; persistence
    contains only its SHA-256 digest.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.managed_trial_invitation import (
        ManagedTrialInvitationConfigurationError,
        ManagedTrialInvitationError,
        get_managed_trial_invitation_store,
        issue_managed_trial_invitation,
        managed_trial_invitations_enabled,
    )

    if not managed_trial_invitations_enabled():
        raise HTTPException(status_code=404, detail="Not found")
    _require_managed_trial_operator(request)

    def _issue_invitation() -> tuple[str, Any]:
        tenant_id = _new_invited_tenant_id(req.organization)
        issued = issue_managed_trial_invitation(
            get_managed_trial_invitation_store(),
            email=req.email,
            tenant_id=tenant_id,
            team_name=req.organization.strip(),
        )
        return tenant_id, issued

    try:
        tenant_id, issued = await anyio.to_thread.run_sync(_issue_invitation)
    except ManagedTrialInvitationConfigurationError as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    except ManagedTrialInvitationError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc, generic=True)) from exc

    try:
        log_action(
            "auth.managed_trial_invitation_created",
            actor=_request_actor(request),
            resource=f"managed-trial-invitation/{issued.invitation.invitation_id}",
            tenant_id=tenant_id,
            details={"state": issued.invitation.state, "expires_at": issued.invitation.expires_at.isoformat()},
        )
    except Exception:
        # The token cannot be recovered after this response; an audit backend
        # outage must not strand a live invitation before the operator sees it.
        _logger.warning("Managed-trial invitation creation audit write failed")
    base = (env_raw("AGENT_BOM_HOSTED_INVITE_BASE_URL") or "").strip()
    login_url = f"{base.rstrip('/')}/login" if base else None
    return {
        "invitation_id": issued.invitation.invitation_id,
        "token": issued.raw_token,
        "tenant_id": tenant_id,
        "role": "analyst",
        "state": issued.invitation.state,
        "created_at": issued.invitation.created_at.isoformat(),
        "expires_at": issued.invitation.expires_at.isoformat(),
        "login_url": login_url,
        "message": "Deliver the token once through a trusted adapter; it cannot be recovered later.",
    }


def _require_managed_trial_operator(request: Request) -> None:
    """Keep cross-tenant trial operations in the reserved operator boundary."""

    configured = env_raw("AGENT_BOM_PLATFORM_OPERATOR_TENANT_ID", "default").strip() or "default"
    if require_request_tenant_id(request) != configured:
        raise HTTPException(status_code=403, detail="Managed-trial operator operations require the platform operator tenant")


def _trial_lifecycle_payload(record: Any) -> dict[str, Any]:
    return {
        "tenant_id": record.tenant_id,
        "state": record.state.value,
        "created_at": record.created_at.isoformat(),
        "trial_ends_at": record.trial_ends_at.isoformat(),
        "cleanup_after": record.cleanup_after.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "cleanup_attempts": record.cleanup_attempts,
        "cleanup_pending": record.state.value == "expired",
        "cleanup_error": record.cleanup_error,
        "cleanup_completed_at": record.cleanup_completed_at.isoformat() if record.cleanup_completed_at else None,
    }


@router.get("/auth/trial-tenants/{tenant_id}", **documented(ManagedTrialTenantResponse), tags=["enterprise"])
async def get_managed_trial_tenant(request: Request, tenant_id: str) -> dict[str, Any]:
    """Return lifecycle and cleanup status for one operator-managed trial."""

    from agent_bom.api.tenant_lifecycle import TenantLifecycleError, get_tenant_lifecycle_store
    from agent_bom.platform_invariants import validate_customer_tenant_id

    _require_managed_trial_operator(request)
    target = validate_customer_tenant_id(tenant_id)

    def _load_record() -> Any:
        return get_tenant_lifecycle_store().get(target)

    try:
        record = await anyio.to_thread.run_sync(_load_record)
    except TenantLifecycleError as exc:
        raise HTTPException(status_code=404, detail="Managed-trial tenant not found") from exc
    return _trial_lifecycle_payload(record)


async def _transition_managed_trial_tenant(
    request: Request,
    tenant_id: str,
    *,
    action: str,
) -> dict[str, Any]:
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.tenant_lifecycle import (
        TenantLifecycleError,
        TenantLifecycleState,
        get_tenant_lifecycle_store,
        revoke_tenant_access,
    )
    from agent_bom.platform_invariants import validate_customer_tenant_id

    _require_managed_trial_operator(request)
    target = validate_customer_tenant_id(tenant_id)

    def _apply_transition() -> tuple[Any, dict[str, int]]:
        store = get_tenant_lifecycle_store()
        try:
            if action == "suspend":
                revoked = revoke_tenant_access(target)
                record = store.transition(target, state=TenantLifecycleState.SUSPENDED)
            elif action == "resume":
                revoked = {}
                record = store.transition(target, state=TenantLifecycleState.ACTIVE)
            elif action == "revoke":
                revoked = revoke_tenant_access(target)
                record = store.transition(target, state=TenantLifecycleState.EXPIRED)
            elif action == "retry-cleanup":
                from agent_bom.api.tenant_lifecycle import delete_tenant_records

                current = store.get(target)
                if current.state is not TenantLifecycleState.EXPIRED:
                    raise TenantLifecycleError("Cleanup may only run for an expired tenant")
                deleted = delete_tenant_records(target)
                record = store.transition(target, state=TenantLifecycleState.DELETED)
                revoked = {"deleted_records": sum(deleted.values())}
            else:
                raise TenantLifecycleError("Unsupported lifecycle action")
        except Exception as exc:
            if action == "retry-cleanup" and not isinstance(exc, TenantLifecycleError):
                store.record_cleanup_failure(target, error=sanitize_error(exc, generic=True))
            raise
        return record, revoked

    try:
        record, revoked = await anyio.to_thread.run_sync(_apply_transition)
    except TenantLifecycleError as exc:
        raise HTTPException(status_code=409, detail=sanitize_error(exc, generic=True)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    log_action(
        f"auth.managed_trial_tenant_{action.replace('-', '_')}",
        actor=_request_actor(request),
        resource=f"managed-trial-tenant/{target}",
        tenant_id=target,
        details={"state": record.state.value, "effects": revoked},
    )
    payload = _trial_lifecycle_payload(record)
    payload["effects"] = revoked
    return payload


@router.post("/auth/trial-tenants/{tenant_id}/suspend", tags=["enterprise"])
async def suspend_managed_trial_tenant(request: Request, tenant_id: str) -> dict[str, Any]:
    return await _transition_managed_trial_tenant(request, tenant_id, action="suspend")


@router.post("/auth/trial-tenants/{tenant_id}/resume", tags=["enterprise"])
async def resume_managed_trial_tenant(request: Request, tenant_id: str) -> dict[str, Any]:
    return await _transition_managed_trial_tenant(request, tenant_id, action="resume")


@router.post("/auth/trial-tenants/{tenant_id}/revoke", tags=["enterprise"])
async def revoke_managed_trial_tenant(request: Request, tenant_id: str) -> dict[str, Any]:
    return await _transition_managed_trial_tenant(request, tenant_id, action="revoke")


@router.post("/auth/trial-tenants/{tenant_id}/cleanup/retry", tags=["enterprise"])
async def retry_managed_trial_tenant_cleanup(request: Request, tenant_id: str) -> dict[str, Any]:
    return await _transition_managed_trial_tenant(request, tenant_id, action="retry-cleanup")
