"""Bounded, content-free retry timing shared by provider readers."""

import math
from datetime import UTC
from email.utils import parsedate_to_datetime


def retry_after_seconds(value: str | None, *, now: float) -> float | None:
    """Parse a finite delay or HTTP date; invalid timing has no usable value."""
    if not value or not value.strip():
        return None
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=UTC)
            seconds = date.timestamp() - now
        except (ValueError, TypeError, OverflowError):
            return None
    return max(0.0, seconds) if math.isfinite(seconds) else None


def provider_retry_after(value: str | None, *, now: float) -> float:
    """Parse HTTP delta-seconds or a date, bounded to one day; invalid means zero."""
    return min(86400, retry_after_seconds(value, now=now) or 0)
