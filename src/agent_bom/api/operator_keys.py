"""Seed API keys from operator configuration idempotently.

Operator keys (``AGENT_BOM_API_KEYS``, ``configure_api(api_key=...)`` / a key
file) are owned by configuration: they never expire, every configured slot
maps to one stable key id so restarts and replicas upsert the same row, and a
slot no longer configured is revoked in the store and rejected at verify time.
"""

from __future__ import annotations

from agent_bom.api.auth import OPERATOR_KEY_ID_PREFIX, Role, create_api_key_record, get_key_store, register_operator_key_ids


def parse_env_api_keys(configured: str) -> list[tuple[str, str, Role]]:
    """Parse ``AGENT_BOM_API_KEYS`` (``<raw-key>:<role>`` comma list) into seed entries."""
    entries: list[tuple[str, str, Role]] = []
    for idx, item in enumerate(configured.split(","), start=1):
        raw_item = item.strip()
        if not raw_item:
            continue
        raw_key, sep, role_value = raw_item.partition(":")
        if not sep or not raw_key.strip() or not role_value.strip():
            raise RuntimeError("AGENT_BOM_API_KEYS entries must use '<raw-key>:<admin|analyst|viewer>' format")
        try:
            role = Role(role_value.strip().lower())
        except ValueError as exc:
            raise RuntimeError(f"Invalid AGENT_BOM_API_KEYS role {role_value!r}; expected admin, analyst, or viewer") from exc
        entries.append((raw_key.strip(), f"env:{role.value}:{idx}", role))
    return entries


def operator_key_id(source: str, slot: int) -> str:
    return f"{OPERATOR_KEY_ID_PREFIX}{source}-{slot}"


def seed_operator_keys(source: str, entries: list[tuple[str, str, Role]]) -> bool:
    """Upsert ``(raw_key, name, role)`` entries for ``source`` and retire its unconfigured slots."""
    store = get_key_store()
    key_ids = [operator_key_id(source, slot) for slot in range(1, len(entries) + 1)]
    for key_id, (raw_key, name, role) in zip(key_ids, entries):
        store.add(create_api_key_record(raw_key, name, role, key_id=key_id, never_expires=True))
    register_operator_key_ids(source, key_ids)
    if entries:
        stale_prefix = operator_key_id(source, 0)[:-1]
        for key in store.list_keys(tenant_id="default"):
            if key.key_id.startswith(stale_prefix) and key.key_id not in key_ids and not key.is_revoked():
                store.remove(key.key_id)
    return bool(entries)
