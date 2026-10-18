"""Bounded, content-free retry timing shared by provider readers."""

from email.utils import parsedate_to_datetime


def provider_retry_after(value: str | None, *, now: float) -> float:
    """Parse HTTP delta-seconds or a date, bounded to one day; invalid means zero."""
    if not value:
        return 0
    value = value.strip()
    try:
        seconds = float(value) if value.isascii() and value.isdigit() else parsedate_to_datetime(value).timestamp() - now
        return min(86400, max(0, seconds))
    except (ValueError, TypeError, OverflowError):
        return 0
