"""Record signing-key continuity without storing the signing key.

This local receipt is not independent tamper evidence. A changed ephemeral key
means old HMACs cannot be checked; it does not establish that rows were changed.
Configured-key verification still checks every signature and checkpoint.
"""

from __future__ import annotations

import hashlib


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
    fingerprint = hashlib.sha256(key).hexdigest()
    existing = connection.execute("SELECT fingerprint FROM audit_key_identity WHERE singleton = 1").fetchone()
    if existing:
        return str(existing[0])
    count = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    # A legacy database has no key-continuity receipt. Do not claim a mismatch
    # is tampering when its old ephemeral key may simply have been lost.
    initial = "legacy-key-unrecorded" if count else fingerprint
    connection.execute("INSERT OR IGNORE INTO audit_key_identity VALUES (1, ?)", (initial,))
    connection.commit()
    return str(connection.execute("SELECT fingerprint FROM audit_key_identity WHERE singleton = 1").fetchone()[0])


def control_plane_integrity(store, *, limit: int, tenant_id: str) -> dict:
    from agent_bom.api import audit_log

    unavailable = (
        isinstance(store, audit_log.SQLiteAuditLog)
        and store._hmac_key is None
        and not audit_log._HMAC_ENV_KEY
        and store._original_key_identity != hashlib.sha256(audit_log._default_signing_key()).hexdigest()
    )
    if unavailable:
        count = min(limit, store.count(tenant_id=tenant_id))
        return {
            "verified": 0,
            "tampered": 0,
            "unverifiable": count,
            "checked": count,
            "error": "Cannot verify: signing key changed or the previous ephemeral key is unavailable.",
        }
    try:
        verified, tampered = store.verify_integrity(limit=limit, tenant_id=tenant_id)
    except AuditVerificationLimitExceededError as exc:
        return {
            "verified": 0,
            "tampered": 0,
            "unverifiable": limit,
            "checked": limit,
            "error": f"Cannot verify: {exc.total} entries exceed the requested limit of {limit}; no complete chain was checked.",
        }
    return {"verified": verified, "tampered": tampered, "unverifiable": 0, "checked": verified + tampered}
