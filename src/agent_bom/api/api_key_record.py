"""Stored API key record, its verification and the operator-key registry.

Dependency-free of the key stores so every backend can share one record type.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone

from agent_bom.core.permission_scopes import scopes_allow
from agent_bom.rbac import Role, role_rank

# Keys seeded from operator configuration (AGENT_BOM_API_KEYS, a runtime
# --api-key / key file) use stable ids under this prefix. They are valid only
# while this process's configuration still names them, so removing a key from
# config retires it even when the persisted row cannot be updated.
OPERATOR_KEY_ID_PREFIX = "operator-"
_active_operator_key_ids: dict[str, frozenset[str]] = {}


def register_operator_key_ids(source: str, key_ids: list[str]) -> None:
    """Record which operator key ids ``source`` currently configures."""
    _active_operator_key_ids[source] = frozenset(key_ids)


@dataclass
class ApiKey:
    """Stored API key metadata (the raw key is never stored)."""

    key_id: str
    key_hash: str  # scrypt KDF of the raw key
    key_salt: str  # hex-encoded salt for scrypt
    key_prefix: str  # First 8 chars for identification
    name: str
    role: Role
    created_at: str = ""
    expires_at: str | None = None
    scopes: list[str] = field(default_factory=list)
    tenant_id: str = "default"
    revoked_at: str | None = None
    rotation_overlap_until: str | None = None
    replacement_key_id: str | None = None
    scim_subject_id: str | None = None
    # Stable identifier of the user this key was issued on behalf of (SCIM
    # user_id / user_name / external_id). Lets deprovisioning revoke free-form
    # CI keys whose ``name`` doesn't match the departing user.
    owner: str | None = None
    # Canonical stable principal id this key is bound to. Set at creation
    # (explicit → scim_subject_id → owner). Deprovisioning a subject revokes
    # every key keyed to its principal_id, independent of the display ``name``.
    principal_id: str | None = None

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if not value:
            return None
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if not self.expires_at:
            return False
        current = now or datetime.now(timezone.utc)
        expires_at = self._parse_timestamp(self.expires_at)
        return bool(expires_at and current > expires_at)

    def is_revoked(self) -> bool:
        return bool(self.revoked_at)

    def is_within_rotation_overlap(self, *, now: datetime | None = None) -> bool:
        if not self.replacement_key_id or not self.rotation_overlap_until:
            return False
        current = now or datetime.now(timezone.utc)
        overlap_until = self._parse_timestamp(self.rotation_overlap_until)
        return bool(overlap_until and current <= overlap_until)

    def is_retired_operator_key(self) -> bool:
        """A config-seeded key whose slot is no longer configured in this process."""
        if not self.key_id.startswith(OPERATOR_KEY_ID_PREFIX):
            return False
        return not any(self.key_id in ids for ids in _active_operator_key_ids.values())

    def is_usable(self, *, now: datetime | None = None) -> bool:
        if self.is_revoked() or self.is_retired_operator_key():
            return False
        if self.is_expired(now=now):
            return False
        if self.replacement_key_id:
            return self.is_within_rotation_overlap(now=now)
        return True

    def lifecycle_state(self, *, now: datetime | None = None) -> str:
        if self.is_revoked() or self.is_retired_operator_key():
            return "revoked"
        if self.is_expired(now=now):
            return "expired"
        if self.replacement_key_id:
            return "rotation_overlap" if self.is_within_rotation_overlap(now=now) else "rotated"
        return "active"

    def has_role(self, required: Role) -> bool:
        """Check if this key's role meets or exceeds the required role."""
        return role_rank(self.role) >= role_rank(required)

    def has_scope(self, required_scope: str | None) -> bool:
        """Check whether this key's scopes allow the requested action."""
        return scopes_allow(self.scopes, required_scope)

    def to_dict(self) -> dict:
        current = datetime.now(timezone.utc)
        overlap_remaining_seconds = None
        if self.rotation_overlap_until:
            overlap_until = self._parse_timestamp(self.rotation_overlap_until)
            if overlap_until is not None:
                overlap_remaining_seconds = max(0, int((overlap_until - current).total_seconds()))
        return {
            "key_id": self.key_id,
            "key_prefix": self.key_prefix,
            "name": self.name,
            "role": self.role.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "scopes": self.scopes,
            "tenant_id": self.tenant_id,
            "revoked_at": self.revoked_at,
            "rotation_overlap_until": self.rotation_overlap_until,
            "replacement_key_id": self.replacement_key_id,
            "scim_subject_id": self.scim_subject_id,
            "owner": self.owner,
            "principal_id": self.principal_id,
            "state": self.lifecycle_state(now=current),
            "overlap_seconds_remaining": overlap_remaining_seconds,
        }


def _derive_key(raw_key: str, salt: bytes) -> str:
    """Derive key hash using scrypt KDF (CodeQL-safe, brute-force resistant)."""
    derived = hashlib.scrypt(
        raw_key.encode(),
        salt=salt,
        n=16384,  # CPU/memory cost (2^14)
        r=8,  # block size
        p=1,  # parallelization
        dklen=32,
    )
    return derived.hex()


def verify_api_key(raw_key: str, stored_keys: list[ApiKey]) -> ApiKey | None:
    """Verify a raw API key against stored keys.

    Uses scrypt KDF with per-key salt and constant-time comparison.
    Returns the matching ApiKey if found and not expired, else None.
    """
    key_prefix = raw_key[:12]
    candidates = [stored for stored in stored_keys if stored.key_prefix == key_prefix]
    for stored in candidates:
        salt = bytes.fromhex(stored.key_salt)
        candidate = _derive_key(raw_key, salt)
        if hmac.compare_digest(stored.key_hash, candidate):
            if not stored.is_usable():
                return None
            return stored
    return None
