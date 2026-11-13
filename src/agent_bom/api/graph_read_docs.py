"""OpenAPI documentation for retryable current-estate graph reads."""

from __future__ import annotations

from typing import Any

from agent_bom.api.current_graph_builds import BUILDING_CODE, ROTATING_CODE
from agent_bom.api.error_models import ErrorEnvelope
from agent_bom.demo_estate.boot_seed import SEEDING_CODE

ROTATING_RESPONSE: dict[str, Any] = {
    "model": ErrorEnvelope,
    "description": (
        f"Retryable: the demo estate is still being seeded (error.details.code ``{SEEDING_CODE}``), or "
        f"the current graph is being prepared (``{BUILDING_CODE}``), or unpinned reads kept landing on retired generations "
        f"(``{ROTATING_CODE}``). Wait "
        "``Retry-After`` seconds and retry; a pinned ``snapshot_generation`` that changed is a 409 instead."
    ),
    "headers": {"Retry-After": {"description": "Seconds to wait before retrying", "schema": {"type": "integer"}}},
}
