"""The stale label: an open finding whose asset has not been re-checked lately.

Computed from ``last_seen`` at read time, so it never rewrites history and a
stale finding stays open and counted. It never resolves anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom import config


def stale_cutoff(now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)) - timedelta(days=max(1, config.FINDING_STALE_DAYS))


def stale_cutoff_text() -> str:
    """The cutoff in the shape stored ``last_seen`` values sort by."""
    return stale_cutoff().strftime("%Y-%m-%dT%H:%M:%SZ")


def is_stale(row: Mapping[str, Any]) -> bool:
    if str(row.get("status") or "open").strip().lower() == "resolved":
        return False
    raw = row.get("last_seen")
    if not isinstance(raw, str) or not raw.strip():
        return False
    try:
        seen = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return False
    return (seen if seen.tzinfo else seen.replace(tzinfo=timezone.utc)) < stale_cutoff()
