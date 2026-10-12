"""Persisted retry scheduling: one provider attempt per user request, never a retry storm."""

import random
from email.utils import parsedate_to_datetime


def provider_retry_after(value: str | None, *, now: float) -> float:
    if not value:
        return 0
    try:
        seconds = float(value) if value.isdigit() else parsedate_to_datetime(value).timestamp() - now
        return min(86400, max(0, seconds))
    except (ValueError, TypeError, OverflowError):
        return 0


def retry_delay(failures: int, *, retry_after: float = 0, jitter: float | None = None) -> float:
    base = min(3600, 60 * 2 ** min(6, max(0, failures - 1)))
    # Scheduling jitter is not a security token.
    spread = random.random() if jitter is None else jitter  # nosec B311
    return max(retry_after, min(3600, base * (1 + 0.25 * spread)))
