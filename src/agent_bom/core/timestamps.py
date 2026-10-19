"""ISO timestamp parsing shared by evidence, scheduling and identity decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_timestamp(raw: Any, *, require_timezone: bool = False) -> datetime | None:
    """Return an aware UTC datetime; invalid input yields None.

    Naive dates/times mean UTC unless the caller requires an explicit zone.
    Accept the trailing Z (or z) emitted by providers as a UTC offset.
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    # Tolerate the trailing-Z form some IdPs emit.
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        if require_timezone:
            return None
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# Keep the existing public identity parser path, including its strict mode.
parse_identity_timestamp = parse_timestamp
