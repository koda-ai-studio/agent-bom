"""Persisted retry scheduling: one provider attempt per user request, never a retry storm."""

import random

from agent_bom.core.http_retry import provider_retry_after as provider_retry_after


def retry_delay(failures: int, *, retry_after: float = 0, jitter: float | None = None) -> float:
    base = min(3600, 60 * 2 ** min(6, max(0, failures - 1)))
    # Scheduling jitter is not a security token.
    spread = random.random() if jitter is None else jitter  # nosec B311
    return max(retry_after, min(3600, base * (1 + 0.25 * spread)))
