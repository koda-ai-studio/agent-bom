"""Recorded graph times: a defaulted node/edge time resolves to its graph's time.

``UnifiedNode``/``UnifiedEdge`` still fill a missing time on construction so a
standalone object is never timeless, but they record which fields were filled
from the clock. Adding the object to a graph replaces those fields with the
graph's ``created_at`` (the scan or snapshot time), so the same input builds
the same graph and no time claims an observation at build or read time.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode


def normalize_recorded_time(value: object) -> str:
    """ISO-8601 UTC to the second, matching graph defaults; ``""`` when unparseable."""
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text)
        except ValueError:
            return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def _instant(value: str) -> datetime | None:
    normalized = normalize_recorded_time(value)
    return datetime.fromisoformat(normalized) if normalized else None


def earlier(a: str, b: str) -> str:
    return _pick(a, b, later=False)


def later(a: str, b: str) -> str:
    return _pick(a, b, later=True)


def _pick(a: str, b: str, *, later: bool) -> str:
    if not a or not b:
        return a or b
    ta, tb = _instant(a), _instant(b)
    if ta is None or tb is None:
        return b if later else a
    if later:
        return b if tb > ta else a
    return b if tb < ta else a


def stamp_node(node: UnifiedNode, at: str) -> None:
    """Resolve clock-defaulted node times to the graph's recorded time."""
    fields = node._clock_defaulted
    if not fields or not at:
        return
    for name in fields:
        setattr(node, name, at)
    node._clock_defaulted = ()


def stamp_edge(edge: UnifiedEdge, at: str) -> None:
    """Resolve clock-defaulted edge times to the graph's recorded time."""
    fields = edge._clock_defaulted
    if not fields or not at:
        return
    for name in fields:
        setattr(edge, name, at)
    edge._clock_defaulted = ()


def merge_seen(existing: UnifiedNode, incoming: UnifiedNode) -> None:
    """A merged node spans the earliest first and the latest last observation."""
    existing.first_seen = earlier(existing.first_seen, incoming.first_seen)
    existing.last_seen = later(existing.last_seen, incoming.last_seen)
