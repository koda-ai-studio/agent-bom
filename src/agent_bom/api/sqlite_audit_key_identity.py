"""Signing-key identity and boundaries for the SQLite audit log.

The identity is a salted HMAC. Testing a candidate key against it costs about one
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
