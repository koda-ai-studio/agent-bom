"""Server-stamped inbound-path sources that corroborate ``graph_reachable``.

``graph_reachable`` means any inbound attack path reaches the finding. The
read-time projection that joins persisted snapshot paths stamps the path
source node ids (``graph_reachable_from``) and their count; nothing a client
sends may supply them, so every persistence path strips them first.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

MAX_REACH_SOURCES = 20
SERVER_STAMPED_REACH_FIELDS = ("graph_reachable_from", "graph_reachable_from_count")
CLIENT_REACH_CLAIM_FIELDS = (*SERVER_STAMPED_REACH_FIELDS, "graph_reachable_from_agents")


def without_fields(payload: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Copy ``payload`` without ``fields``."""
    return {key: value for key, value in payload.items() if key not in fields}


def stamp_reach_sources(row: dict[str, Any], sources: set[str]) -> None:
    """Record a bounded, sorted source sample and the exact source count."""
    row["graph_reachable_from"] = sorted(sources)[:MAX_REACH_SOURCES]
    row["graph_reachable_from_count"] = len(sources)


def safe_reach_sources(row: Mapping[str, Any], safe_text: Callable[[Any], str | None]) -> tuple[list[str], int | None]:
    """Validated source sample and count for a response payload."""
    raw = row.get("graph_reachable_from")
    sources = [text for value in (raw[:MAX_REACH_SOURCES] if isinstance(raw, list) else []) if (text := safe_text(value)) is not None]
    count = row.get("graph_reachable_from_count")
    valid_count = count if isinstance(count, int) and not isinstance(count, bool) and count >= len(sources) else None
    return sources, (valid_count if sources else None)
