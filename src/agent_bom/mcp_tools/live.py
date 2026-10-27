"""Shared server policy for caller-requested live MCP collection."""

from __future__ import annotations

from agent_bom.core.settings import TRUTHY, env_opt

LIVE_INTROSPECTION_ENV = "AGENT_BOM_MCP_LIVE_INTROSPECTION"


def live_introspection_allowed() -> bool:
    """Unset permits a caller opt-in; an explicit non-yes setting refuses it."""
    value = env_opt(LIVE_INTROSPECTION_ENV)
    return value is None or value.strip().lower() in TRUTHY


def live_collection_denial(live: bool) -> dict[str, str] | None:
    """Return an honest not-collected response before any credential or network use."""
    if not live:
        return {"status": "not_collected", "error": "Live Kubernetes collection requires live=true."}
    if not live_introspection_allowed():
        return {"status": "not_collected", "error": f"Live collection is disabled by {LIVE_INTROSPECTION_ENV}."}
    return None
