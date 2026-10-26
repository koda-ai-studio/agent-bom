"""Role-based access control (RBAC) and API key management.

Provides API key creation, verification, and role-based endpoint protection
for enterprise deployments.
"""

from __future__ import annotations

import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from agent_bom.api.api_key_record import OPERATOR_KEY_ID_PREFIX as OPERATOR_KEY_ID_PREFIX
from agent_bom.api.api_key_record import ApiKey as ApiKey
from agent_bom.api.api_key_record import _derive_key
from agent_bom.api.api_key_record import register_operator_key_ids as register_operator_key_ids
from agent_bom.api.api_key_record import verify_api_key as verify_api_key
from agent_bom.api.sqlite_key_store import SQLiteKeyStore
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.core.permission_scopes import scopes_allow as scopes_allow
from agent_bom.core.settings import env_str
from agent_bom.rbac import Role, role_rank


@dataclass(frozen=True)
class ApiKeyPolicy:
    """Operator-controlled API key lifetime policy."""

    default_ttl_seconds: int = 30 * 24 * 60 * 60
    max_ttl_seconds: int = 90 * 24 * 60 * 60
    default_overlap_seconds: int = 0
    max_overlap_seconds: int = 24 * 60 * 60


@dataclass(frozen=True)
class SCIMRoleResolution:
    """Runtime auth role resolved from tenant-bound SCIM lifecycle state."""

    matched: bool
    active: bool
    role: Role | None = None
    user_id: str | None = None
    user_name: str | None = None


def _dedupe_subjects(subjects: tuple[object, ...]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for subject in subjects:
        candidate = str(subject or "").strip()
        if not candidate:
            continue
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _highest_role(values: list[str]) -> Role | None:
    best: Role | None = None
    for value in values:
        try:
            candidate = Role(str(value).strip().lower())
        except ValueError:
            continue
        if best is None or role_rank(candidate) > role_rank(best):
            best = candidate
    return best


def resolve_scim_user_role(tenant_id: str, *subjects: object) -> SCIMRoleResolution:
    """Resolve an active SCIM user's highest role within one tenant.

    The resolver is intentionally tenant-scoped and only matches indexed SCIM
    identity fields so runtime auth does not scan all provisioned users.
    """

    from agent_bom.api.scim import scim_enabled_from_env

    if not scim_enabled_from_env():
        return SCIMRoleResolution(matched=False, active=False)

    candidates = _dedupe_subjects(subjects)
    if not tenant_id or not candidates:
        return SCIMRoleResolution(matched=False, active=False)

    from agent_bom.api.stores import _get_scim_store
    from agent_bom.platform_invariants import normalize_tenant_id

    tenant = normalize_tenant_id(tenant_id)
    users = []
    seen_users: set[str] = set()
    store = _get_scim_store()
    for subject in candidates:
        for attr in ("userName", "externalId", "id"):
            for user in store.list_users(tenant, filter_attr=attr, filter_value=subject):
                key = f"{user.tenant_id}:{user.user_id}"
                if key not in seen_users:
                    seen_users.add(key)
                    users.append(user)

    if not users:
        return SCIMRoleResolution(matched=False, active=False)

    active_users = [user for user in users if user.active]
    if not active_users:
        user = users[0]
        return SCIMRoleResolution(matched=True, active=False, user_id=user.user_id, user_name=user.user_name)

    best_user = active_users[0]
    best_role: Role | None = None
    for user in active_users:
        role = _highest_role(user.roles)
        if role is None:
            role = Role.VIEWER
        if best_role is None or role_rank(role) > role_rank(best_role):
            best_role = role
            best_user = user

    return SCIMRoleResolution(matched=True, active=True, role=best_role, user_id=best_user.user_id, user_name=best_user.user_name)


async def resolve_scim_user_role_async(tenant_id: str, *subjects: object) -> SCIMRoleResolution:
    """Recheck SCIM source presence per request; keep configured file/store reads off-loop."""
    from starlette.concurrency import run_in_threadpool

    from agent_bom.api.scim import _SCIM_SINGLE_TOKEN_ENV, _SCIM_TOKEN_MAPPING_ENV

    sources = (_SCIM_SINGLE_TOKEN_ENV, f"{_SCIM_SINGLE_TOKEN_ENV}_FILE", _SCIM_TOKEN_MAPPING_ENV)
    if not any(env_str(name, "") for name in sources):
        return SCIMRoleResolution(matched=False, active=False)
    return await run_in_threadpool(resolve_scim_user_role, tenant_id, *subjects)


def resolve_scim_subject_binding(request: object, explicit: str | None = None) -> str | None:
    """Resolve the SCIM subject id to persist on a newly issued API key.

    Precedence: explicit request field → runtime SCIM resolution on the session →
    parent key binding → canonical SCIM user id for OIDC/SAML callers.
    """
    if explicit and str(explicit).strip():
        return str(explicit).strip()

    state = getattr(request, "state", request)
    state_user_id = getattr(state, "scim_user_id", None)
    if state_user_id:
        return str(state_user_id)

    bound = getattr(state, "scim_subject_id", None)
    if bound:
        return str(bound)

    key_id = getattr(state, "api_key_id", None)
    if key_id:
        parent = get_key_store().get(str(key_id))
        if parent and parent.scim_subject_id:
            return parent.scim_subject_id

    tenant_id = getattr(state, "tenant_id", None) or "default"
    auth_method = str(getattr(state, "auth_method", "") or "")
    api_key_name = str(getattr(state, "api_key_name", "") or "")
    if auth_method in {"saml", "oidc", "browser_session"} and api_key_name:
        subjects: tuple[object, ...] = (api_key_name.removeprefix("saml:"), api_key_name)
        resolution = resolve_scim_user_role(tenant_id, *subjects)
        if resolution.user_id:
            return resolution.user_id
    return None


def get_api_key_policy() -> ApiKeyPolicy:
    """Load API key lifetime policy from env with safe defaults."""
    default_ttl = int(os.environ.get("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS", str(30 * 24 * 60 * 60)))
    max_ttl = int(os.environ.get("AGENT_BOM_API_KEY_MAX_TTL_SECONDS", str(90 * 24 * 60 * 60)))
    default_overlap = int(os.environ.get("AGENT_BOM_API_KEY_DEFAULT_OVERLAP_SECONDS", "0"))
    max_overlap = int(os.environ.get("AGENT_BOM_API_KEY_MAX_OVERLAP_SECONDS", str(24 * 60 * 60)))
    if default_ttl <= 0:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS must be > 0")
    if max_ttl <= 0:
        raise ValueError("AGENT_BOM_API_KEY_MAX_TTL_SECONDS must be > 0")
    if default_ttl > max_ttl:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS cannot exceed AGENT_BOM_API_KEY_MAX_TTL_SECONDS")
    if default_overlap < 0:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_OVERLAP_SECONDS must be >= 0")
    if max_overlap < 0:
        raise ValueError("AGENT_BOM_API_KEY_MAX_OVERLAP_SECONDS must be >= 0")
    if default_overlap > max_overlap:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_OVERLAP_SECONDS cannot exceed AGENT_BOM_API_KEY_MAX_OVERLAP_SECONDS")
    return ApiKeyPolicy(
        default_ttl_seconds=default_ttl,
        max_ttl_seconds=max_ttl,
        default_overlap_seconds=default_overlap,
        max_overlap_seconds=max_overlap,
    )


def normalize_api_key_expiry(
    expires_at: str | None,
    *,
    now: datetime | None = None,
    policy: ApiKeyPolicy | None = None,
) -> str:
    """Normalize and enforce API key expiry under the configured policy."""
    active_policy = policy or get_api_key_policy()
    current = now or datetime.now(timezone.utc)
    if expires_at:
        try:
            parsed = datetime.fromisoformat(expires_at)
        except ValueError as exc:
            raise ValueError("expires_at must be a valid ISO-8601 datetime with timezone") from exc
        if parsed.tzinfo is None:
            raise ValueError("expires_at must include timezone information")
        if parsed <= current:
            raise ValueError("expires_at must be in the future")
        max_expiry = current + timedelta(seconds=active_policy.max_ttl_seconds)
        if parsed > max_expiry:
            raise ValueError(f"expires_at exceeds the maximum allowed API key lifetime ({active_policy.max_ttl_seconds} seconds)")
        return parsed.isoformat()
    return (current + timedelta(seconds=active_policy.default_ttl_seconds)).isoformat()


def normalize_rotation_overlap_seconds(
    overlap_seconds: int | None,
    *,
    policy: ApiKeyPolicy | None = None,
) -> int:
    """Normalize a requested key-rotation overlap window under operator policy."""
    active_policy = policy or get_api_key_policy()
    candidate = active_policy.default_overlap_seconds if overlap_seconds is None else overlap_seconds
    if candidate < 0:
        raise ValueError("overlap_seconds must be >= 0")
    if candidate > active_policy.max_overlap_seconds:
        raise ValueError(f"overlap_seconds exceeds the maximum allowed overlap window ({active_policy.max_overlap_seconds} seconds)")
    return candidate


def create_api_key(
    name: str,
    role: Role,
    expires_at: str | None = None,
    scopes: list[str] | None = None,
    tenant_id: str = "default",
    scim_subject_id: str | None = None,
    owner: str | None = None,
    principal_id: str | None = None,
) -> tuple[str, ApiKey]:
    """Generate a new API key.

    Returns (raw_key, api_key_record). The raw key is only returned once
    and should be given to the user. Only the scrypt-derived hash is stored.
    """
    raw_key = f"abom_{secrets.token_urlsafe(32)}"
    return raw_key, create_api_key_record(
        raw_key,
        name=name,
        role=role,
        expires_at=expires_at,
        scopes=scopes,
        tenant_id=tenant_id,
        scim_subject_id=scim_subject_id,
        owner=owner,
        principal_id=principal_id,
    )


def create_api_key_record(
    raw_key: str,
    name: str,
    role: Role,
    expires_at: str | None = None,
    scopes: list[str] | None = None,
    tenant_id: str = "default",
    scim_subject_id: str | None = None,
    owner: str | None = None,
    principal_id: str | None = None,
    *,
    key_id: str | None = None,
    never_expires: bool = False,
) -> ApiKey:
    """Create a stored API key record for an operator-supplied raw key.

    ``never_expires`` is for keys whose lifetime is owned by operator
    configuration: they rotate by changing that configuration, not by TTL.
    """
    salt = os.urandom(16)
    key_hash = _derive_key(raw_key, salt)
    normalized_expiry = None if never_expires else normalize_api_key_expiry(expires_at)
    owner_normalized = owner.strip() if isinstance(owner, str) and owner.strip() else None
    scim_subject_normalized = scim_subject_id.strip() if isinstance(scim_subject_id, str) and scim_subject_id.strip() else scim_subject_id
    # The canonical stable binding: an explicit principal id wins; otherwise fall
    # back to the SCIM subject id, then the free-form owner, so every key carries
    # a revocation key even when the caller only supplied one of the legacy hints.
    principal_normalized = principal_id.strip() if isinstance(principal_id, str) and principal_id.strip() else None
    resolved_principal = principal_normalized or scim_subject_normalized or owner_normalized
    return ApiKey(
        key_id=key_id or secrets.token_hex(8),
        key_hash=key_hash,
        key_salt=salt.hex(),
        key_prefix=raw_key[:12],
        name=name,
        role=role,
        expires_at=normalized_expiry,
        scopes=scopes or [],
        tenant_id=tenant_id,
        scim_subject_id=scim_subject_id,
        owner=owner_normalized,
        principal_id=resolved_principal,
    )


# ---------------------------------------------------------------------------
# Key store (in-memory singleton)
# ---------------------------------------------------------------------------


class KeyStore:
    """Thread-safe in-memory API key store."""

    def __init__(self) -> None:
        self._keys: list[ApiKey] = []
        self._lock = threading.Lock()

    def add(self, key: ApiKey) -> None:
        with self._lock:
            self._keys = [existing for existing in self._keys if existing.key_id != key.key_id]
            self._keys.append(key)

    def provision_tenant_key(self, key: ApiKey, *, team_name: str) -> None:
        """Provision a tenant's first key for the in-memory self-hosted store.

        The in-memory backend has no separate team registry, so provisioning is
        equivalent to adding the already tenant-scoped key. Persistent stores
        override this method to create their tenant FK root atomically.
        """
        del team_name
        self.add(key)

    def remove(self, key_id: str) -> bool:
        with self._lock:
            for key in self._keys:
                if key.key_id == key_id and not key.is_revoked():
                    key.revoked_at = datetime.now(timezone.utc).isoformat()
                    key.rotation_overlap_until = None
                    return True
            return False

    def revoke_by_principal_id(self, principal_id: str, tenant_id: str | None = None) -> list[str]:
        """Revoke every active key bound to ``principal_id`` and return their ids.

        Id-based, complete revocation: a deprovisioned subject loses all of its
        keys regardless of display ``name``. Scoped to ``tenant_id`` when given so
        one tenant's deprovision never revokes another tenant's identically-keyed
        credentials.
        """
        if not principal_id:
            return []
        revoked: list[str] = []
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            for key in self._keys:
                if key.principal_id != principal_id or key.is_revoked():
                    continue
                if tenant_id is not None and key.tenant_id != tenant_id:
                    continue
                key.revoked_at = now
                key.rotation_overlap_until = None
                revoked.append(key.key_id)
        return revoked

    def mark_rotating(self, key_id: str, *, replacement_key_id: str, overlap_until: str) -> bool:
        with self._lock:
            for key in self._keys:
                if key.key_id == key_id and not key.is_revoked():
                    key.replacement_key_id = replacement_key_id
                    key.rotation_overlap_until = overlap_until
                    return True
            return False

    def get(self, key_id: str) -> ApiKey | None:
        with self._lock:
            return next((k for k in self._keys if k.key_id == key_id), None)

    def list_keys(self, tenant_id: str | None = None) -> list[ApiKey]:
        with self._lock:
            keys = list(self._keys)
        if tenant_id is None:
            return keys
        return [k for k in keys if k.tenant_id == tenant_id]

    def delete_tenant(self, tenant_id: str) -> int:
        """Permanently remove every key belonging to one confirmed tenant purge."""
        with self._lock:
            before = len(self._keys)
            self._keys = [key for key in self._keys if key.tenant_id != tenant_id]
            return before - len(self._keys)

    def verify(self, raw_key: str) -> ApiKey | None:
        # Hold the lock only long enough to snapshot the key list; the expensive
        # scrypt derivation in ``verify_api_key`` then runs lock-free so it
        # neither stalls the caller under the lock nor serializes concurrent
        # verifies (each worker thread derives independently). ``is_usable()`` is
        # still evaluated at match time, so revocation/expiry semantics are
        # unchanged.
        with self._lock:
            keys_snapshot = list(self._keys)
        return verify_api_key(raw_key, keys_snapshot)

    def has_keys(self) -> bool:
        with self._lock:
            return len(self._keys) > 0


class KeyStoreProtocol(Protocol):
    """Interface shared by in-memory and persistent API key stores."""

    def add(self, key: ApiKey) -> None: ...
    def provision_tenant_key(self, key: ApiKey, *, team_name: str) -> None: ...
    def remove(self, key_id: str) -> bool: ...
    def revoke_by_principal_id(self, principal_id: str, tenant_id: str | None = None) -> list[str]: ...
    def mark_rotating(self, key_id: str, *, replacement_key_id: str, overlap_until: str) -> bool: ...
    def get(self, key_id: str) -> ApiKey | None: ...
    def list_keys(self, tenant_id: str | None = None) -> list[ApiKey]: ...
    def delete_tenant(self, tenant_id: str) -> int: ...
    def verify(self, raw_key: str) -> ApiKey | None: ...
    def has_keys(self) -> bool: ...


_key_store: KeyStoreProtocol | None = None
_store_lock = threading.Lock()


def get_key_store() -> KeyStoreProtocol:
    global _key_store
    if _key_store is None:
        with _store_lock:
            if _key_store is None:
                db_path = env_str("AGENT_BOM_DB")
                if postgres_deployment_configured():
                    from agent_bom.api.postgres_access import PostgresKeyStore

                    _key_store = PostgresKeyStore()
                elif db_path and db_path != ":memory:":
                    _key_store = SQLiteKeyStore(db_path)
                else:
                    _key_store = KeyStore()
    return _key_store


def key_store_is_durable(store: KeyStoreProtocol | None = None) -> bool:
    """Whether minted keys survive an API restart (False for the process-local store)."""
    return not isinstance(store if store is not None else get_key_store(), KeyStore)


NON_DURABLE_KEY_WARNING = (
    "This key is held in API process memory only and stops working when the API restarts. "
    "Run the API with a database (agent-bom serve --persist, AGENT_BOM_DB or AGENT_BOM_POSTGRES_URL) for durable keys."
)


def key_durability_fields(store: KeyStoreProtocol | None = None) -> dict[str, object]:
    """Response fields telling the caller whether a minted key survives a restart."""
    if key_store_is_durable(store):
        return {"durable": True}
    return {"durable": False, "warning": NON_DURABLE_KEY_WARNING}


def set_key_store(store: KeyStoreProtocol) -> None:
    global _key_store
    with _store_lock:
        _key_store = store
