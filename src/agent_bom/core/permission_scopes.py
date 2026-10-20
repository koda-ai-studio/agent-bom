"""Pure matching of granted permission scopes against an operation scope."""

from __future__ import annotations


def scopes_allow(granted_scopes: list[str], required_scope: str | None) -> bool:
    """Return whether a scope set authorizes one requested scope.

    An empty granted set is the legacy unrestricted representation. Callers
    that delegate credentials must separately prevent a scoped parent from
    minting that unrestricted representation.
    """
    if not required_scope or not granted_scopes:
        return True
    for scope in granted_scopes:
        if scope == "*" or scope == required_scope:
            return True
        if scope.endswith(":*") and required_scope.startswith(scope[:-1]):
            return True
        if scope.endswith(".*") and required_scope.startswith(scope[:-1]):
            return True
    return False
