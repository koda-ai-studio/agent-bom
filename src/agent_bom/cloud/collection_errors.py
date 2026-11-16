"""Typed, fixed diagnostics at provider inventory boundaries.

Never copy provider exception text or response bodies into inventory warnings.
Successful empty collections produce no warning; failed reads remain incomplete.
"""

from __future__ import annotations

from enum import Enum

import httpx

from agent_bom.http_client import OfflineModeError

from .base import CloudDiscoveryError


class CollectionStatus(str, Enum):
    COMPLETE = "complete"
    EMPTY = "empty"
    DENIED = "denied"
    THROTTLED = "throttled"
    UNAVAILABLE = "unavailable"


# Transport, explicit provider failures, and malformed external record shapes.
# Programming errors outside these data/transport boundaries are not swallowed.
COLLECTION_ERRORS = (OfflineModeError, httpx.HTTPError, CloudDiscoveryError, OSError, ValueError, TypeError, AttributeError, KeyError)


def collection_status(exc: Exception) -> CollectionStatus:
    """Classify structured status only; exception messages are untrusted."""
    code = getattr(getattr(exc, "response", None), "status_code", None)
    return {401: CollectionStatus.DENIED, 403: CollectionStatus.DENIED, 429: CollectionStatus.THROTTLED}.get(
        code if isinstance(code, int) else 0, CollectionStatus.UNAVAILABLE
    )


def collection_warning(provider: str, resource: str, exc: Exception) -> str:
    status = collection_status(exc)
    guidance = {
        CollectionStatus.DENIED: "Check credentials and read permissions.",
        CollectionStatus.THROTTLED: "Provider rate limit reached; retry later.",
        CollectionStatus.UNAVAILABLE: "Provider read failed or returned invalid data; retry or check availability.",
    }
    return f"{provider}:{resource}:{status.value}: {guidance[status]} Assessment incomplete."


def inventory_list(data: object, *keys: str) -> list:
    """Accept an explicit list, never infer empty from an unrelated envelope."""
    if isinstance(data, dict):
        data = next((data[key] for key in keys if key in data), None)
    if not isinstance(data, list):
        raise CloudDiscoveryError("Invalid inventory collection")
    return data
