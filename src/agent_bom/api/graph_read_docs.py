"""OpenAPI documentation for retryable current-estate graph reads."""

from __future__ import annotations

from typing import Any

from agent_bom.api.current_graph import ROTATING_CODE, SEEDING_CODE
from agent_bom.api.error_models import ErrorEnvelope

ROTATING_RESPONSE: dict[str, Any] = {
    "model": ErrorEnvelope,
    "description": (
        f"Retryable: the demo estate is still being seeded (error.details.code ``{SEEDING_CODE}``), or "
        f"unpinned current-estate reads kept landing on retired generations (``{ROTATING_CODE}``). Wait "
        "``Retry-After`` seconds and retry; a pinned ``snapshot_generation`` that changed is a 409 instead."
    ),
    "headers": {"Retry-After": {"description": "Seconds to wait before retrying", "schema": {"type": "integer"}}},
}
