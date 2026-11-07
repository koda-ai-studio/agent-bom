"""Record signing-key continuity without storing the signing key or a plain digest of it.

This local receipt is not independent tamper evidence. A changed ephemeral key
means old HMACs cannot be checked; it does not establish that rows were changed.
Configured-key verification still checks every signature and checkpoint.

The receipt is a salted HMAC. Testing a candidate key against it costs about one
HMAC-SHA-256, which is what the stored audit HMACs already allow over known row
contents, so it adds no offline guessing route, and the salt rules out tables
computed in advance. A slow derivation here would protect nothing, because an
attacker would use the audit rows instead. Use a high-entropy signing key.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_IDENTITY_PREFIX = "v2"
_LEGACY_UNRECORDED = "legacy-key-unrecorded"


def _salted_identity(key_digest: bytes, salt: bytes) -> str:
    derived = hmac.digest(key_digest, b"audit-key-identity\x00" + salt, "sha256").hex()
    return f"{_IDENTITY_PREFIX}:{salt.hex()}:{derived}"


def new_key_identity(key: bytes) -> str:
    return _salted_identity(hashlib.sha256(key).digest(), secrets.token_bytes(16))


def key_matches_identity(key: bytes, stored: str) -> bool:
    """Compare a signing key with a stored identity without revealing either."""
    parts = stored.split(":")
    if len(parts) != 3 or parts[0] != _IDENTITY_PREFIX:
        return False
    try:
        salt = bytes.fromhex(parts[1])
    except ValueError:
        return False
    return hmac.compare_digest(_salted_identity(hashlib.sha256(key).digest(), salt), stored)


def _is_unsalted_digest(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


class AuditVerificationLimitExceededError(ValueError):
    """A full chain cannot be checked within the requested entry budget."""

    def __init__(self, total: int, limit: int):
        self.total, self.limit = total, limit
        super().__init__("Audit verification entry budget exceeded")


def require_verification_budget(total: int, limit: int) -> None:
    if total > limit:
        raise AuditVerificationLimitExceededError(total, limit)


def record_key_identity(connection, key: bytes) -> str:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS audit_key_identity (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), fingerprint TEXT NOT NULL)"
    )
    existing = connection.execute("SELECT fingerprint FROM audit_key_identity WHERE singleton = 1").fetchone()
    if existing:
        stored = str(existing[0])
        if not _is_unsalted_digest(stored):
            return stored
        # An earlier release stored SHA-256(key). The upgrade needs only that
        # digest, so it also covers rows whose original key is gone, and a key
        # that matched before still matches afterwards.
        replacement = _salted_identity(bytes.fromhex(stored), secrets.token_bytes(16))
        connection.execute("UPDATE audit_key_identity SET fingerprint = ? WHERE singleton = 1 AND fingerprint = ?", (replacement, stored))
        connection.commit()
        return str(connection.execute("SELECT fingerprint FROM audit_key_identity WHERE singleton = 1").fetchone()[0])
    count = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    # A legacy database has no key-continuity receipt. Do not claim a mismatch
    # is tampering when its old ephemeral key may simply have been lost.
    initial = _LEGACY_UNRECORDED if count else new_key_identity(key)
    connection.execute("INSERT OR IGNORE INTO audit_key_identity VALUES (1, ?)", (initial,))
    connection.commit()
    return str(connection.execute("SELECT fingerprint FROM audit_key_identity WHERE singleton = 1").fetchone()[0])


def _cannot_verify(count: int) -> dict:
    return {
        "verified": 0,
        "tampered": 0,
        "unverifiable": count,
        "checked": count,
        "error": "Cannot verify with this key: the signing key changed or the previous key is unavailable.",
    }


def control_plane_integrity(store, *, limit: int, tenant_id: str) -> dict:
    from agent_bom.api import audit_log

    is_local = isinstance(store, audit_log.SQLiteAuditLog)
    identity = store._original_key_identity if is_local else ""
    key = (store._hmac_key or audit_log._default_signing_key()) if is_local else b""
    recorded = bool(identity) and identity != _LEGACY_UNRECORDED
    configured = is_local and (store._hmac_key is not None or bool(audit_log._HMAC_ENV_KEY))
    # A recorded identity tells a different key from altered rows exactly. An old
    # log without one, on an ephemeral key, cannot be told apart at all.
    if is_local and ((recorded and not key_matches_identity(key, identity)) or (not recorded and not configured)):
        return _cannot_verify(min(limit, store.count(tenant_id=tenant_id)))
    try:
        verified, tampered = store.verify_integrity(limit=limit, tenant_id=tenant_id)
    except AuditVerificationLimitExceededError as exc:
        # Nothing was walked, so no count of verified rows exists: null, never zero.
        return {
            "verified": None,
            "tampered": 0,
            "unverifiable": exc.total,
            "checked": 0,
            "status": "not_verified_over_budget",
            "total_entries": exc.total,
            "verification_limit": limit,
            "error": (
                f"Not verified: {exc.total} entries exceed the requested limit of {limit}, so no chain was checked. "
                "Request a higher limit, up to 10,000 here, or verify offline with an explicitly larger budget."
            ),
        }
    # With no recorded identity, every row failing means a different key or a
    # complete rewrite, and neither is a clean result nor proof of tampering.
    identity_known = is_local and recorded
    if not identity_known and type(store).__name__ != "InMemoryAuditLog" and not verified and tampered:
        total = store.count(tenant_id=tenant_id)
        if tampered >= total > 0:
            return _cannot_verify(total)
    return {"verified": verified, "tampered": tampered, "unverifiable": 0, "checked": verified + tampered}
