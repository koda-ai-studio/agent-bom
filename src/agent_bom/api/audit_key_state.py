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


def _boundary_signature(key: bytes, first_rowid: int) -> str:
    return hmac.digest(key, b"audit-key-boundary\x00" + str(first_rowid).encode(), "sha256").hex()


def _record_key_boundary(connection, key: bytes, *, signed_every_row: bool) -> None:
    """Record, under this key, the row from which it signs the log.

    Rows from there on must verify, so a failure is tampering. Only the key's
    holder can write a valid boundary, so an edit to this table cannot excuse a
    row. A key already latest needs nothing new.
    """
    connection.execute("CREATE TABLE IF NOT EXISTS audit_key_boundary (first_rowid INTEGER NOT NULL, signature TEXT NOT NULL)")
    latest = connection.execute("SELECT first_rowid, signature FROM audit_key_boundary ORDER BY rowid DESC LIMIT 1").fetchone()
    if latest and hmac.compare_digest(str(latest[1]), _boundary_signature(key, int(latest[0]))):
        return
    highest = connection.execute("SELECT COALESCE(MAX(rowid), 0) FROM audit_log").fetchone()[0]
    # A key matching the identity recorded before boundaries existed signed everything since.
    first_rowid = 0 if not highest or (signed_every_row and latest is None) else int(highest) + 1
    connection.execute(
        "INSERT INTO audit_key_boundary (first_rowid, signature) VALUES (?, ?)", (first_rowid, _boundary_signature(key, first_rowid))
    )
    connection.commit()


def _key_required_rowids(connection, key: bytes) -> list[tuple[int, int | None]] | None:
    """Row ranges this key must have signed, from each boundary it signed to the next of any key.

    None when it signed no boundary. Opening the log once with a wrong key adds
    only an empty range, so returning to the right key loses no detection.
    """
    rows = connection.execute("SELECT first_rowid, signature FROM audit_key_boundary ORDER BY first_rowid, rowid").fetchall()
    ranges: list[tuple[int, int | None]] = []
    for index, (first_rowid, signature) in enumerate(rows):
        if hmac.compare_digest(str(signature), _boundary_signature(key, int(first_rowid))):
            ranges.append((int(first_rowid), int(rows[index + 1][0]) if index + 1 < len(rows) else None))
    return ranges or None


def record_key_identity(connection, key: bytes) -> str:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS audit_key_identity (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), fingerprint TEXT NOT NULL)"
    )
    existing = connection.execute("SELECT fingerprint FROM audit_key_identity WHERE singleton = 1").fetchone()
    if existing:
        stored = str(existing[0])
        if _is_unsalted_digest(stored):
            # An earlier release stored SHA-256(key). The upgrade needs only that
            # digest, so it also covers rows whose original key is gone, and a key
            # that matched before still matches afterwards.
            replacement = _salted_identity(bytes.fromhex(stored), secrets.token_bytes(16))
            connection.execute(
                "UPDATE audit_key_identity SET fingerprint = ? WHERE singleton = 1 AND fingerprint = ?", (replacement, stored)
            )
            connection.commit()
    else:
        count = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        # A legacy database has no key-continuity receipt. Do not claim a mismatch
        # is tampering when its old ephemeral key may simply have been lost.
        initial = _LEGACY_UNRECORDED if count else new_key_identity(key)
        connection.execute("INSERT OR IGNORE INTO audit_key_identity VALUES (1, ?)", (initial,))
        connection.commit()
    identity = str(connection.execute("SELECT fingerprint FROM audit_key_identity WHERE singleton = 1").fetchone()[0])
    _record_key_boundary(connection, key, signed_every_row=key_matches_identity(key, identity))
    return identity


def _classify_chain(entries: list, checkpoint, key: bytes | None, required: list[tuple[int, int | None]] | None) -> dict:
    """Score each row by what the held key can establish.

    Links and the stored count and head need no key, so they are always exact.
    A row that fails its signature is tampered when the key must have signed it.
    Elsewhere no held key can check it, which is reported as such. With no signed
    boundary, the key must have signed every row after the first it verifies.
    ``required`` holds row positions, as start and exclusive end.
    """
    signed = [entry.verify(key) for entry in entries]
    if required is None:
        required = [(next((index for index, ok in enumerate(signed) if ok), len(entries)), None)]
    verified = tampered = unverifiable = 0
    previous = ""
    for index, entry in enumerate(entries):
        if entry.prev_signature != previous:
            tampered += 1
        elif signed[index]:
            verified += 1
        elif any(start <= index and (end is None or index < end) for start, end in required):
            tampered += 1
        else:
            unverifiable += 1
        previous = entry.hmac_signature
    if checkpoint is not None and (
        len(entries) != checkpoint.entry_count or (entries and entries[-1].hmac_signature != checkpoint.head_signature)
    ):
        tampered += 1
    return {"verified": verified, "tampered": tampered, "unverifiable": unverifiable}


def _chain_counts(store, audit_log, *, limit: int, tenant_id: str) -> dict | None:
    """Per-row result for stores that can be walked here; others answer with one key only."""
    if isinstance(store, audit_log.SQLiteAuditLog):
        total = store.count(tenant_id=tenant_id)
        require_verification_budget(total, limit)
        entries = store._list_entries_chronological(limit=total or limit, tenant_id=tenant_id)
        key = store._hmac_key or audit_log._default_signing_key()
        rowids = _key_required_rowids(store._conn, key)

        def position(rowid: int) -> int:
            return store._conn.execute("SELECT COUNT(*) FROM audit_log WHERE tenant_id = ? AND rowid < ?", (tenant_id, rowid)).fetchone()[0]

        required = None if rowids is None else [(position(start), None if end is None else position(end)) for start, end in rowids]
        return _classify_chain(entries, store._get_checkpoint(tenant_id), key, required)
    if type(store).__name__ == "PostgresAuditLog":
        from agent_bom.api.postgres_audit import _tenant_scope

        with _tenant_scope(tenant_id):
            total = store.count(tenant_id=tenant_id)
            require_verification_budget(total, limit)
            entries = store._list_entries_chronological(limit=total or limit, tenant_id=tenant_id)
            checkpoint = store._get_checkpoint(tenant_id)
        return _classify_chain(entries, checkpoint, None, None)
    return None


def _unverifiable_explanation(*, has_boundary: bool, verified: int, unverifiable: int, total: int) -> str:
    prefix = f"Cannot verify {unverifiable} of {total} entries with this key."
    if has_boundary:
        return (
            f"{prefix} They were written before this signing key was first used: the signing key changed "
            "or the previous key is unavailable. Changes to their contents are not detected until checked with that key; "
            "their order and count still are. Later entries are verified exactly."
        )
    if not verified:
        return (
            f"{prefix} A different signing key and every entry having been altered cannot be told apart here, "
            "because this store keeps no record of the key. Check with the key that wrote them."
        )
    return (
        f"{prefix} They precede the first entry this key verifies. A different earlier key and altered contents "
        "cannot be told apart here, because this store keeps no record of the key."
    )


def control_plane_integrity(store, *, limit: int, tenant_id: str) -> dict:
    from agent_bom.api import audit_log

    try:
        counts = _chain_counts(store, audit_log, limit=limit, tenant_id=tenant_id)
        if counts is None:
            verified, tampered = store.verify_integrity(limit=limit, tenant_id=tenant_id)
            counts = {"verified": verified, "tampered": tampered, "unverifiable": 0}
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
    checked = counts["verified"] + counts["tampered"] + counts["unverifiable"]
    if not counts["unverifiable"]:
        return {**counts, "checked": checked}
    return {
        **counts,
        "checked": checked,
        "status": "partially_unverifiable",
        "error": _unverifiable_explanation(
            has_boundary=isinstance(store, audit_log.SQLiteAuditLog),
            verified=counts["verified"],
            unverifiable=counts["unverifiable"],
            total=checked,
        ),
    }
