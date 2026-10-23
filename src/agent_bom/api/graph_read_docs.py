"""OpenAPI documentation for retryable current-estate graph reads."""

from __future__ import annotations

from typing import Any

from agent_bom.api.current_graph import ROTATING_CODE
from agent_bom.api.error_models import ErrorEnvelope

ROTATING_RESPONSE: dict[str, Any] = {
    "model": ErrorEnvelope,
    "description": (
        f"Retryable: unpinned current-estate reads kept landing on retired generations (error.details.code "
        f"``{ROTATING_CODE}``). Wait ``Retry-After`` seconds and retry; a pinned ``snapshot_generation`` "
        "that changed is a 409 instead."
    ),
    "headers": {"Retry-After": {"description": "Seconds to wait before retrying", "schema": {"type": "integer"}}},
}
