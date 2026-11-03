"""Which declared MCP HTTP header names carry authentication (names only, never values)."""

from __future__ import annotations

from collections.abc import Iterable

AUTH_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "apikey",
        "x-apikey",
        "x-auth-token",
        "x-access-token",
        "x-goog-api-key",
    }
)
_AUTH_HINTS = ("auth", "token", "api-key", "apikey", "api_key")


def is_auth_header(name: object) -> bool:
    if not isinstance(name, str):
        return False
    low = name.strip().lower()
    return low in AUTH_HEADER_NAMES or any(hint in low for hint in _AUTH_HINTS)


def auth_header_names(names: Iterable[object]) -> list[str]:
    """Return the declared header names that carry authentication, in input order."""
    return [name for name in names if isinstance(name, str) and is_auth_header(name)]
