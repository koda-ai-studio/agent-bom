"""Bound explicit benchmark scopes without falling back to ambient credentials."""

from collections.abc import Sequence

from agent_bom.cloud.base import CloudDiscoveryError


def bounded_scope_ids(scopes: Sequence[str], limit: int, label: str) -> tuple[list[str], list[str]]:
    """Normalize a scope set and retain a receipt when a collection cap applies."""
    ids = sorted({value.strip() for value in scopes if isinstance(value, str) and value.strip()})
    if not ids:
        raise CloudDiscoveryError(f"No {label} resolved for the requested benchmark scope.")
    maximum = max(1, limit)
    warnings = [f"Benchmark capped at {maximum} of {len(ids)} {label}."] if len(ids) > maximum else []
    return ids[:maximum], warnings
