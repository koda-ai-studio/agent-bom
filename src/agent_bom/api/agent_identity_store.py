"""Agent identity lifecycle: issue, rotate, revoke, and verify.

``agent_bom.agent_identity`` verifies identity tokens an external IdP issues but
never managed their lifecycle. This store lets agent-bom issue time-scoped
identities for agents that have no IdP, rotate them with an overlap window, and
revoke them — the provisioning/rotation/revocation layer an agent-identity
control plane needs. Issued tokens (``abi_<prefix>_<secret>``) are stored only
as SHA-256 hashes; the raw token is returned exactly once at issue/rotate time.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.identity_grants import (
    AgentJITGrant as AgentJITGrant,
)
from agent_bom.api.identity_grants import (
    approve_jit_grant as approve_jit_grant,
)
from agent_bom.api.identity_grants import (
    deny_jit_grant as deny_jit_grant,
)
from agent_bom.api.identity_grants import (
    identity_expiry as _ttl_to_expiry,
)
from agent_bom.api.identity_grants import (
    issue_jit_grant as issue_jit_grant,
)
from agent_bom.api.identity_grants import (
    request_jit_grant as request_jit_grant,
)
from agent_bom.api.identity_grants import (
    revoke_jit_grant as revoke_jit_grant,
)
from agent_bom.api.identity_local_store import (
    InMemoryAgentIdentityStore as InMemoryAgentIdentityStore,
)
from agent_bom.api.identity_local_store import (
    SQLiteAgentIdentityStore as SQLiteAgentIdentityStore,
)
from agent_bom.api.identity_local_store import (
    _table_columns as _table_columns,
)
from agent_bom.api.identity_models import (
    AgentIdentity as AgentIdentity,
)
from agent_bom.api.identity_models import (
    AgentIdentityStore as AgentIdentityStore,
)
from agent_bom.api.identity_policies import (
    AccessContext as AccessContext,
)
from agent_bom.api.identity_policies import (
    ConditionalAccessPolicy as ConditionalAccessPolicy,
)
from agent_bom.api.identity_policies import (
    create_conditional_policy as create_conditional_policy,
)
from agent_bom.api.identity_policies import (
    evaluate_conditional_access as evaluate_conditional_access,
)
from agent_bom.api.identity_policies import (
    evaluate_conditional_access_for_request as evaluate_conditional_access_for_request,
)
from agent_bom.api.identity_policies import (
    set_conditional_policy_status as set_conditional_policy_status,
)
from agent_bom.core.settings import env_int

TOKEN_PREFIX = "abi"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> tuple[str, str, str]:
    """Return ``(raw_token, public_prefix, token_hash)``. Raw token is shown once."""
    public = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    raw = f"{TOKEN_PREFIX}_{public}_{secret}"
    return raw, public, hash_token(raw)


# ── Lifecycle operations ────────────────────────────────────────────────────────


def issue_identity(
    store: AgentIdentityStore,
    *,
    agent_id: str,
    tenant_id: str,
    role: str = "agent",
    blueprint_id: str = "",
    ttl_seconds: int = 90 * 86400,
    allowed_tools: list[str] | None = None,
    owner: str = "",
    owner_type: str = "",
) -> tuple[AgentIdentity, str]:
    """Issue a new identity. Returns ``(identity, raw_token)``; the raw token is
    only available here and at rotation.

    ``owner`` records the accountable principal (human / team / service) for the
    issued identity and is preserved across rotation; pass it so the identity is
    owner-bound at birth rather than orphaned.
    """
    raw, prefix, token_hash = generate_token()
    now = _now()
    identity = AgentIdentity(
        identity_id=f"id_{secrets.token_hex(8)}",
        agent_id=agent_id,
        tenant_id=tenant_id,
        token_hash=token_hash,
        token_prefix=prefix,
        role=role,
        blueprint_id=blueprint_id,
        status="active",
        issued_at=_iso(now),
        expires_at=_ttl_to_expiry(ttl_seconds, at=now),
        allowed_tools=list(allowed_tools or []),
        owner=str(owner or "").strip()[:200],
        owner_type=str(owner_type or "").strip()[:60],
    )
    store.put(identity)
    return identity, raw


def identity_for_token(store: AgentIdentityStore, token: str) -> AgentIdentity | None:
    """Resolve a raw token to its live managed identity, or None.

    Used by the runtime relay to enforce per-tool scopes; returns None for
    unknown or non-live (revoked/expired) tokens.
    """
    identity = store.get_by_token_hash(hash_token(token))
    if identity is None or not identity.is_live():
        return None
    return identity


def rotate_identity(
    store: AgentIdentityStore,
    identity_id: str,
    *,
    tenant_id: str,
    overlap_seconds: int = 3600,
    ttl_seconds: int = 90 * 86400,
) -> tuple[AgentIdentity, str] | None:
    """Issue a replacement identity and keep the old one live for ``overlap_seconds``
    so in-flight callers are not cut off. Returns ``(new_identity, raw_token)``."""
    old = store.get(identity_id, tenant_id=tenant_id)
    # Don't rotate a revoked identity, or one already mid-rotation (that would
    # orphan the first replacement and break the rotated_to chain).
    if old is None or old.status in ("revoked", "rotating"):
        return None
    new_identity, raw = issue_identity(
        store,
        agent_id=old.agent_id,
        tenant_id=old.tenant_id,
        role=old.role,
        blueprint_id=old.blueprint_id,
        ttl_seconds=ttl_seconds,
        allowed_tools=old.allowed_tools,
        owner=old.owner,
        owner_type=old.owner_type,
    )
    now = _now()
    old.status = "rotating"
    old.rotated_to_id = new_identity.identity_id
    old.expires_at = _ttl_to_expiry(overlap_seconds, at=now)
    store.put(old)
    return new_identity, raw


def revoke_identity(store: AgentIdentityStore, identity_id: str, *, tenant_id: str, reason: str = "") -> AgentIdentity | None:
    """Immediately revoke an identity; it can no longer authenticate."""
    identity = store.get(identity_id, tenant_id=tenant_id)
    if identity is None:
        return None
    identity.status = "revoked"
    identity.revoked_at = _iso(_now())
    identity.revoked_reason = reason[:500]
    store.put(identity)
    return identity


# Upper bound on identities fetched per revocation check. The agent-keyed
# lookup bounds one agent's own rotation history, which no deployment approaches,
# so the cap is not reachable in practice. A store that predates
# ``list_by_agent`` still has to page the tenant roster by recency; there the cap
# IS reachable, and hitting it means an older revoked row may sit in the
# untraversed tail. That case reports the lookup as incomplete — an honest
# partial signal the caller fails closed on — rather than a confident "not
# revoked". Mirrors ``_DRIFT_INCIDENT_LOOKUP_CAP`` in the gateway.
_IDENTITY_LOOKUP_CAP = 5000


def identities_for_agent(store: AgentIdentityStore, tenant_id: str, agent_id: str) -> tuple[list[AgentIdentity], bool]:
    """Return ``(identities_for_agent, lookup_was_incomplete)`` for one tenant.

    Reads the agent's own identities through an indexed lookup so the tenant's
    roster size cannot hide a revoked row. Falls back to the recency-capped
    roster scan only for a store that does not implement ``list_by_agent``.
    """
    key = (agent_id or "").strip()
    if not key:
        return [], False
    by_agent = getattr(store, "list_by_agent", None)
    if by_agent is not None:
        rows = by_agent(tenant_id, key, limit=_IDENTITY_LOOKUP_CAP)
        return [i for i in rows if (i.agent_id or "").strip() == key], False
    rows = store.list(tenant_id, include_inactive=True, limit=_IDENTITY_LOOKUP_CAP)
    capped = len(rows) >= _IDENTITY_LOOKUP_CAP
    return [i for i in rows if (i.agent_id or "").strip() == key], capped


def live_identity_for_agent(store: AgentIdentityStore, tenant_id: str, agent_id: str) -> AgentIdentity | None:
    """Return one live identity for ``agent_id``, or ``None`` if every one is dead.

    ``identity_for_token`` resolves by token hash, which only matches an
    agent-bom-issued ``abi_`` token. A caller presenting a JWKS/OIDC JWT or an
    opaque ``policy.agent_tokens`` mapping never reaches the identity store, so
    the gateway needs an agent-keyed lookup to honour revocation for them too.
    """
    identities, _capped = identities_for_agent(store, tenant_id, agent_id)
    for identity in identities:
        if identity.is_live():
            return identity
    return None


def agent_identity_revoked(store: AgentIdentityStore, tenant_id: str, agent_id: str) -> tuple[bool, bool]:
    """Return ``(revoked, lookup_incomplete)`` for ``agent_id`` in one tenant.

    An agent with no managed identity at all is *not* revoked — deployments that
    never issued one must keep working. Rotation also leaves revoked rows behind,
    so a single live identity is enough to keep the agent alive.

    ``lookup_incomplete`` is True when the roster hit the lookup cap and this
    agent had no matching identity: absence is then unproven, not evidence of
    absence, and the caller must not read it as "authorized".
    """
    identities, capped = identities_for_agent(store, tenant_id, agent_id)
    if not identities:
        return False, capped
    return not any(i.is_live() for i in identities), False


def active_jit_grant_for_tool(
    store: AgentIdentityStore,
    *,
    tenant_id: str,
    identity_id: str,
    tool_name: str,
    at: datetime | None = None,
) -> AgentJITGrant | None:
    return store.active_jit_grant(tenant_id, identity_id, tool_name, at=at)


# ── Lifecycle-enforcement sweeps (driven by the API cleanup loop) ─────────────
#
# These transition lingering JIT grants and dormant agent-bom identities to a
# terminal state and surface rotation-due tokens, emitting one append-only,
# hash-chained governance-audit record per action. Every function:
#   • takes an INJECTED ``now`` (never calls datetime.now itself) so results are
#     deterministic and consistent across replicas,
#   • derives a DETERMINISTIC action id from stable target state (so a re-run
#     over identical state produces no duplicate audit row and no double
#     transition — idempotent), and
#   • catches store/DB errors per-row and continues, so a single bad record or a
#     backend hiccup never aborts the sweep (fail-open for cleanup).

_lifecycle_logger = logging.getLogger("agent_bom.api.nhi_lifecycle")

# Quotas/rotation defaults. 0 = disabled for the deprovision window so dormant
# auto-revoke is strictly opt-in; rotation defaults to a 90-day advisory flag.
DEFAULT_TOKEN_ROTATION_DAYS = 90


def _env_int(name: str, default: int) -> int:
    return env_int(name, default, minimum=0, on_invalid="default")


def nhi_deprovision_days() -> int:
    """Dormant agent-identity auto-deprovision window in days.

    Default 0 = DISABLED (opt-in). Operators set
    ``AGENT_BOM_NHI_DEPROVISION_DAYS`` to a positive value to enable automatic
    revocation of agent-bom's own dormant identities. Cloud NHIs are never
    written to — this governs issued ``abi_`` identities only.
    """
    return _env_int("AGENT_BOM_NHI_DEPROVISION_DAYS", 0)


def token_rotation_days() -> int:
    """Token age (days) beyond which an identity is flagged ``rotation_due``."""
    return _env_int("AGENT_BOM_TOKEN_ROTATION_DAYS", DEFAULT_TOKEN_ROTATION_DAYS)


def quota_state(identity: AgentIdentity) -> dict[str, Any]:
    """Return the per-identity quota envelope the gateway will later enforce.

    Pure DATA getter: it reports the configured limits and whether any are set,
    but does not meter usage — request/cost accounting lives in the gateway
    (separate PR). ``enforced`` is True when at least one positive limit exists.
    """
    max_requests = max(0, int(identity.max_requests_per_window or 0))
    max_cost = max(0.0, float(identity.max_cost_usd_per_window or 0.0))
    window = max(0, int(identity.quota_window_seconds or 0))
    return {
        "identity_id": identity.identity_id,
        "tenant_id": identity.tenant_id,
        "max_requests_per_window": max_requests,
        "max_cost_usd_per_window": max_cost,
        "window_seconds": window,
        "enforced": bool((max_requests or max_cost) and window),
    }


def set_identity_quota(
    store: AgentIdentityStore,
    identity_id: str,
    *,
    tenant_id: str,
    max_requests_per_window: int = 0,
    max_cost_usd_per_window: float = 0.0,
    window_seconds: int = 0,
) -> AgentIdentity | None:
    """Record per-identity quota limits (data only; gateway enforces later)."""
    identity = store.get(identity_id, tenant_id=tenant_id)
    if identity is None:
        return None
    identity.max_requests_per_window = max(0, int(max_requests_per_window))
    identity.max_cost_usd_per_window = max(0.0, float(max_cost_usd_per_window))
    identity.quota_window_seconds = max(0, int(window_seconds))
    store.put(identity)
    return identity


def _is_postgres_store(store: AgentIdentityStore) -> bool:
    return type(store).__name__ == "PostgresAgentIdentityStore"


def _put_identity_any_tenant(store: AgentIdentityStore, identity: AgentIdentity) -> None:
    """Persist an identity write that may target a non-ambient tenant.

    The cleanup loop sweeps every tenant, so a write-back for tenant X must
    satisfy that tenant's RLS WITH CHECK. For Postgres we bind X explicitly and
    keep the write on the ordinary app connection; other backends ignore
    tenant scoping on write.
    """
    if _is_postgres_store(store):
        from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

        token = set_current_tenant(identity.tenant_id)
        try:
            store.put(identity)
        finally:
            reset_current_tenant(token)
        return
    store.put(identity)


def _put_grant_any_tenant(store: AgentIdentityStore, grant: AgentJITGrant) -> None:
    if _is_postgres_store(store):
        from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

        token = set_current_tenant(grant.tenant_id)
        try:
            store.put_jit_grant(grant, tenant_id=grant.tenant_id)
        finally:
            reset_current_tenant(token)
        return
    store.put_jit_grant(grant, tenant_id=grant.tenant_id)


def _export_audit_to_otlp(record: Any) -> None:
    """Fire-and-forget OTLP-log export of a sealed audit record.

    Batched + non-blocking (the OTLP batch processor flushes off-thread) and a
    strict no-op unless ``AGENT_BOM_OTEL_LOGS_ENDPOINT`` is configured, so the
    cleanup loop is never blocked or aborted by observability export.
    """
    try:
        from agent_bom.siem.otlp_logs import export_governance_audit_record

        export_governance_audit_record(record)
    except Exception:  # noqa: BLE001 — export must never abort cleanup
        _lifecycle_logger.debug("governance audit OTLP export skipped", exc_info=False)


def _emit_audit(record_kwargs: dict[str, Any], audit_log: Any) -> None:
    """Append one governance-audit record, tolerating a sink failure."""
    if audit_log is None:
        return
    try:
        from agent_bom.api.governance_audit_log import make_governance_audit_record

        record = make_governance_audit_record(**record_kwargs)
        sealed = audit_log.append(record)
        _export_audit_to_otlp(sealed)
    except Exception:  # noqa: BLE001 — an audit-sink hiccup must not abort cleanup
        _lifecycle_logger.warning(
            "governance audit append failed for action=%s target=%s; "
            "check the governance_audit_log backend (SQLite path writable / disk space)",
            record_kwargs.get("action"),
            record_kwargs.get("target_id"),
            exc_info=False,
        )


def cleanup_expired_grants(
    store: AgentIdentityStore,
    *,
    now: datetime,
    audit_log: Any = None,
    actor: str = "system:nhi-cleanup",
    limit: int = 10000,
) -> dict[str, int]:
    """Transition expired ``active`` and lingering ``denied`` JIT grants to terminal.

    An ``active`` grant whose ``expires_at`` has passed becomes ``revoked`` with
    reason ``expired``; a ``denied`` grant becomes ``revoked`` (pruned) so it no
    longer lingers in the active set. The transition is idempotent: a grant
    already ``revoked`` is skipped, and the audit id is derived from the grant id
    + its terminal timestamp, so a second sweep over the same state writes no new
    rows. Never raises; per-grant errors are logged and skipped.
    """
    expired = pruned = errors = 0
    try:
        grants = store.iter_all_jit_grants(limit=limit)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning(
            "JIT-grant cleanup could not list grants; the identity store may be "
            "unreachable (check AGENT_BOM_POSTGRES_URL / DB connectivity). Skipping this tick.",
            exc_info=False,
        )
        return {"expired": 0, "pruned": 0, "errors": 1}

    for grant in grants:
        try:
            if grant.status == "active" and grant.expires_at and now > datetime.fromisoformat(grant.expires_at):
                before = grant.status
                grant.status = "revoked"
                grant.revoked_at = _iso(now)
                grant.revoked_reason = "expired"
                _put_grant_any_tenant(store, grant)
                expired += 1
                _emit_audit(
                    {
                        "tenant_id": grant.tenant_id,
                        "actor": actor,
                        "action": "jit_grant_expired",
                        "target_type": "jit_grant",
                        "target_id": grant.grant_id,
                        "reason": "expired",
                        "before_state": before,
                        "after_state": "revoked",
                        "observed_at": _iso(now),
                        "window_key": grant.expires_at,
                        "detail": {"identity_id": grant.identity_id, "tool_name": grant.tool_name},
                    },
                    audit_log,
                )
            elif grant.status == "denied":
                before = grant.status
                window_key = grant.denied_at or grant.requested_at
                grant.status = "revoked"
                grant.revoked_at = _iso(now)
                grant.revoked_reason = "denied_pruned"
                _put_grant_any_tenant(store, grant)
                pruned += 1
                _emit_audit(
                    {
                        "tenant_id": grant.tenant_id,
                        "actor": actor,
                        "action": "jit_grant_denied_pruned",
                        "target_type": "jit_grant",
                        "target_id": grant.grant_id,
                        "reason": "denied_pruned",
                        "before_state": before,
                        "after_state": "revoked",
                        "observed_at": _iso(now),
                        "window_key": window_key,
                        "detail": {"identity_id": grant.identity_id, "tool_name": grant.tool_name},
                    },
                    audit_log,
                )
        except (ValueError, TypeError):
            errors += 1
            _lifecycle_logger.warning("skipping JIT grant %s with unparseable timestamps", grant.grant_id)
        except Exception:  # noqa: BLE001 — one bad write must not abort the sweep
            errors += 1
            _lifecycle_logger.warning("failed to clean up JIT grant %s; continuing", grant.grant_id, exc_info=False)

    return {"expired": expired, "pruned": pruned, "errors": errors}


def deprovision_dormant_identities(
    store: AgentIdentityStore,
    *,
    now: datetime,
    dormant_days: int | None = None,
    audit_log: Any = None,
    actor: str = "system:nhi-cleanup",
    limit: int = 10000,
) -> dict[str, int]:
    """Revoke agent-bom's OWN identities dormant beyond the configured window.

    DISABLED by default (``dormant_days`` 0 / ``AGENT_BOM_NHI_DEPROVISION_DAYS``
    unset): operators opt in. Only ``active``/``rotating`` issued identities with
    a ``last_used_at`` older than the window are revoked, with reason
    ``dormant_auto_revoke``. Cloud principals are not touched — this store only
    holds agent-bom-issued identities. Idempotent + injected ``now``; never
    raises into the loop.
    """
    window = dormant_days if dormant_days is not None else nhi_deprovision_days()
    if window <= 0:
        return {"revoked": 0, "errors": 0, "disabled": 1}

    revoked = errors = 0
    try:
        identities = store.iter_all_identities(limit=limit)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning(
            "dormant-identity sweep could not list identities; the identity store may be "
            "unreachable (check DB connectivity). Skipping this tick.",
            exc_info=False,
        )
        return {"revoked": 0, "errors": 1, "disabled": 0}

    for identity in identities:
        try:
            if identity.status not in ("active", "rotating"):
                continue
            last_used = identity.last_used_at.strip() if identity.last_used_at else ""
            if not last_used:
                # Never-observed identities are not auto-revoked here: lack of a
                # usage marker can mean a freshly issued token, not dormancy. The
                # graph governance overlay still surfaces them as findings.
                continue
            last_used_dt = datetime.fromisoformat(last_used)
            age_days = (now - last_used_dt).total_seconds() / 86400.0
            if age_days < window:
                continue
            before = identity.status
            identity.status = "revoked"
            identity.revoked_at = _iso(now)
            identity.revoked_reason = "dormant_auto_revoke"
            _put_identity_any_tenant(store, identity)
            revoked += 1
            _emit_audit(
                {
                    "tenant_id": identity.tenant_id,
                    "actor": actor,
                    "action": "identity_dormant_auto_revoke",
                    "target_type": "agent_identity",
                    "target_id": identity.identity_id,
                    "reason": "dormant_auto_revoke",
                    "before_state": before,
                    "after_state": "revoked",
                    "observed_at": _iso(now),
                    "window_key": identity.revoked_at,
                    "detail": {
                        "agent_id": identity.agent_id,
                        "owner": identity.owner,
                        "owner_type": identity.owner_type,
                        "last_used_at": last_used,
                        "window_days": window,
                    },
                },
                audit_log,
            )
        except (ValueError, TypeError):
            errors += 1
            _lifecycle_logger.warning("skipping identity %s with unparseable last_used_at", identity.identity_id)
        except Exception:  # noqa: BLE001
            errors += 1
            _lifecycle_logger.warning("failed to deprovision identity %s; continuing", identity.identity_id, exc_info=False)

    return {"revoked": revoked, "errors": errors, "disabled": 0}


def flag_rotation_due_identities(
    store: AgentIdentityStore,
    *,
    now: datetime,
    rotation_days: int | None = None,
    audit_log: Any = None,
    actor: str = "system:nhi-cleanup",
    limit: int = 10000,
) -> dict[str, int]:
    """Advisory: flag identities whose token age exceeds the rotation window.

    Sets ``rotation_due=True`` (and ``rotation_due_at``) on live identities whose
    ``issued_at`` is older than the window. The secret is NOT rotated — an
    operator/automation rotates it explicitly. Idempotent: an identity already
    flagged is skipped (no second audit row); injected ``now``; never raises.
    """
    window = rotation_days if rotation_days is not None else token_rotation_days()
    flagged = errors = 0
    if window <= 0:
        return {"flagged": 0, "errors": 0}
    try:
        identities = store.iter_all_identities(limit=limit)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning(
            "rotation-due sweep could not list identities; the identity store may be unreachable. Skipping this tick.",
            exc_info=False,
        )
        return {"flagged": 0, "errors": 1}

    for identity in identities:
        try:
            if identity.status not in ("active", "rotating") or identity.rotation_due:
                continue
            if not identity.issued_at:
                continue
            issued_dt = datetime.fromisoformat(identity.issued_at)
            age_days = (now - issued_dt).total_seconds() / 86400.0
            if age_days < window:
                continue
            identity.rotation_due = True
            identity.rotation_due_at = _iso(now)
            _put_identity_any_tenant(store, identity)
            flagged += 1
            _emit_audit(
                {
                    "tenant_id": identity.tenant_id,
                    "actor": actor,
                    "action": "token_rotation_due",
                    "target_type": "agent_identity",
                    "target_id": identity.identity_id,
                    "reason": f"token age exceeds {window}d rotation window",
                    "before_state": "rotation_current",
                    "after_state": "rotation_due",
                    "observed_at": _iso(now),
                    "window_key": identity.issued_at,
                    "detail": {
                        "agent_id": identity.agent_id,
                        "owner": identity.owner,
                        "owner_type": identity.owner_type,
                        "issued_at": identity.issued_at,
                        "window_days": window,
                    },
                },
                audit_log,
            )
        except (ValueError, TypeError):
            errors += 1
            _lifecycle_logger.warning("skipping identity %s with unparseable issued_at", identity.identity_id)
        except Exception:  # noqa: BLE001
            errors += 1
            _lifecycle_logger.warning("failed to flag identity %s for rotation; continuing", identity.identity_id, exc_info=False)

    return {"flagged": flagged, "errors": errors}


def run_nhi_lifecycle_cleanup(
    store: AgentIdentityStore,
    *,
    now: datetime,
    audit_log: Any = None,
    dormant_days: int | None = None,
    rotation_days: int | None = None,
) -> dict[str, dict[str, int]]:
    """Run all NHI lifecycle sweeps once. Backend-agnostic; never raises.

    Returns per-sweep counters. Safe to call repeatedly: each sweep is
    idempotent over identical store state, so two consecutive calls produce the
    same end-state and no duplicate audit rows.
    """
    result: dict[str, dict[str, int]] = {}
    try:
        result["grants"] = cleanup_expired_grants(store, now=now, audit_log=audit_log)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning("JIT-grant cleanup sweep failed wholesale; continuing", exc_info=False)
        result["grants"] = {"expired": 0, "pruned": 0, "errors": 1}
    try:
        result["dormant"] = deprovision_dormant_identities(store, now=now, dormant_days=dormant_days, audit_log=audit_log)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning("dormant-identity sweep failed wholesale; continuing", exc_info=False)
        result["dormant"] = {"revoked": 0, "errors": 1, "disabled": 0}
    try:
        result["rotation"] = flag_rotation_due_identities(store, now=now, rotation_days=rotation_days, audit_log=audit_log)
    except Exception:  # noqa: BLE001
        _lifecycle_logger.warning("rotation-due sweep failed wholesale; continuing", exc_info=False)
        result["rotation"] = {"flagged": 0, "errors": 1}
    return result


def verify_token(store: AgentIdentityStore, token: str) -> tuple[str, str | None]:
    """Resolve an agent-bom-issued token to ``(agent_id, error)``.

    Returns a non-None error for revoked, expired, or unknown tokens so the
    gateway/proxy identity check fails closed.
    """
    identity = store.get_by_token_hash(hash_token(token))
    if identity is None:
        return "anonymous", "Unknown agent identity token"
    if identity.status == "revoked":
        return "anonymous", "Agent identity has been revoked"
    if not identity.is_live():
        return "anonymous", "Agent identity has expired"
    return identity.agent_id, None


_AGENT_IDENTITY_STORE: AgentIdentityStore | None = None


def get_agent_identity_store() -> AgentIdentityStore:
    """Return the process agent-identity store, durable by default.

    Selection (highest precedence first), via :mod:`agent_bom.api.durable_store`:
    - Postgres (``AGENT_BOM_POSTGRES_URL`` / ``AGENT_BOM_DB`` Postgres URL):
      multi-replica, tenant RLS — issued tokens, JIT grants, and conditional
      policies stay consistent across every replica.
    - in-memory (``AGENT_BOM_EPHEMERAL_STORE=1``): explicit opt-out; issued
      identities and grants are lost on restart.
    - SQLite (default, or ``AGENT_BOM_DB`` file path): single-node durable —
      identities and grants survive a restart. This is the default; a control
      plane must not drop issued tokens on a single-replica restart.
    """
    global _AGENT_IDENTITY_STORE
    if _AGENT_IDENTITY_STORE is not None:
        return _AGENT_IDENTITY_STORE
    from agent_bom.api.durable_store import select_backend, sqlite_path

    backend = select_backend()
    if backend == "postgres":
        from agent_bom.api.postgres_agent_identity import PostgresAgentIdentityStore

        _AGENT_IDENTITY_STORE = PostgresAgentIdentityStore()
    elif backend == "memory":
        _AGENT_IDENTITY_STORE = InMemoryAgentIdentityStore()
    else:
        _AGENT_IDENTITY_STORE = SQLiteAgentIdentityStore(sqlite_path())
    return _AGENT_IDENTITY_STORE


def set_agent_identity_store(store: AgentIdentityStore | None) -> None:
    global _AGENT_IDENTITY_STORE
    _AGENT_IDENTITY_STORE = store


def register_local_identity_verifier() -> None:
    """Wire the lifecycle store into agent_bom.agent_identity so issued tokens
    resolve (and revoked/expired ones fail closed) in the proxy/gateway."""
    from agent_bom import agent_identity as _ai

    _ai.set_local_identity_verifier(lambda token: verify_token(get_agent_identity_store(), token))
