"""Process-local authenticated loopback bootstrap state, below HTTP composition.

Invalid roles fail closed before replacing the active key. No credentials are
persisted; bind and browser-cookie eligibility remain enforced by their callers.
"""

from __future__ import annotations

from agent_bom.core.settings import env_raw
from agent_bom.rbac import Role

# Ephemeral, per-process loopback dev API key. Only ever set by the CLI
# (`agent-bom serve`) on a LOOPBACK bind when no other auth is configured, so
# the same-origin dashboard can mint a matching browser session and load with
# zero flags. Never persisted; non-loopback binds never set this (the CLI auth
# gate refuses them first). See cli/_server._should_auto_generate_dev_key.
_dev_api_key: str | None = None
_dev_api_role: Role = Role.ADMIN


def set_dev_api_key(raw_key: str | None) -> None:
    """Register (or clear) the ephemeral loopback dev API key for the UI.

    The key itself is seeded into the RBAC key store by ``configure_api``; this
    holder only lets the dashboard HTML routes issue a matching browser-session
    cookie so the first-party same-origin UI authenticates automatically on a
    loopback bind. Process-local and never written to disk.
    """
    global _dev_api_key, _dev_api_role
    value = (raw_key or "").strip() or None
    role = Role.ADMIN
    if value:
        try:
            role = Role((env_raw("AGENT_BOM_NO_AUTH_ROLE") or "admin").strip().lower())
        except ValueError:
            raise ValueError("Invalid explicit loopback role") from None
    _dev_api_key = value
    _dev_api_role = role


def get_dev_api_key() -> str | None:
    """Return the active ephemeral loopback dev API key, if any."""
    return _dev_api_key


def get_dev_api_role() -> Role:
    """Role selected for the active authenticated loopback bootstrap."""
    return _dev_api_role
