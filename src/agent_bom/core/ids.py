"""Byte-preserving digest primitives for existing provider identity formats."""

from hashlib import sha256


def legacy_provider_binding_id(prefix: str, *parts: str) -> str:
    """Preserve the existing UTF-8/unit-separator/24-hex provider ID contract.

    Do not normalize, escape, reorder, or drop empty parts: those operations
    would change persisted IDs. This is a legacy format, not a new identity
    schema; new scoped identities use canonical_ids instead.
    """
    return prefix + sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]
