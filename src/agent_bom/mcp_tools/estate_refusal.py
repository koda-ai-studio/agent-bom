"""The one MCP shape for a current estate that is not ready to read (seeding or rotating generations)."""

from __future__ import annotations

from agent_bom.demo_estate.boot_seed import SEEDING_CODE, SEEDING_MESSAGE, SEEDING_RETRY_AFTER_SECONDS, demo_estate_seeding
from agent_bom.mcp_errors import CODE_UPSTREAM_UNAVAILABLE, mcp_error_json


def seeding_refusal(tenant_id: str, scan_id: str | None = None) -> str | None:
    """The typed refusal for an unpinned estate read while *tenant_id* is being seeded, else ``None``."""
    if scan_id or not demo_estate_seeding(tenant_id):
        return None
    return mcp_error_json(
        CODE_UPSTREAM_UNAVAILABLE, SEEDING_MESSAGE, details={"reason": SEEDING_CODE, "retry_after_seconds": SEEDING_RETRY_AFTER_SECONDS}
    )


def retryable_estate_refusal(exc: BaseException) -> str | None:
    """A typed, retryable MCP error for a current-estate 503, or ``None`` for anything else."""
    detail = getattr(exc, "detail", None)
    if getattr(exc, "status_code", None) != 503 or not isinstance(detail, dict):
        return None
    try:
        retry_after = int((getattr(exc, "headers", None) or {}).get("Retry-After", 1))
    except (TypeError, ValueError):
        retry_after = 1
    return mcp_error_json(
        CODE_UPSTREAM_UNAVAILABLE,
        str(detail.get("message") or "The current estate is not ready; retry the request."),
        details={"reason": str(detail.get("code") or ""), "retry_after_seconds": retry_after},
    )
