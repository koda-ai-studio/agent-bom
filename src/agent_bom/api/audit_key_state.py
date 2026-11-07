"""Record signing-key continuity without storing the signing key or a plain digest of it.

This local receipt is not independent tamper evidence. A changed ephemeral key
means old HMACs cannot be checked; it does not establish that rows were changed.
Configured-key verification still checks every signature and checkpoint.
"""

from __future__ import annotations

from agent_bom.api.sqlite_audit_key_identity import _key_required_rowids, key_matches_identity, record_key_identity

__all__ = [
    "AuditVerificationLimitExceededError",
    "control_plane_integrity",
    "key_matches_identity",
    "record_key_identity",
    "require_verification_budget",
]


class AuditVerificationLimitExceededError(ValueError):
    """A full chain cannot be checked within the requested entry budget."""

    def __init__(self, total: int, limit: int):
        self.total, self.limit = total, limit
        super().__init__("Audit verification entry budget exceeded")


def require_verification_budget(total: int, limit: int) -> None:
    if total > limit:
        raise AuditVerificationLimitExceededError(total, limit)


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
