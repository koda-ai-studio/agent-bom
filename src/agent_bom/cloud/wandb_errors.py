"""Lazy W&B read boundaries without copying SDK exception messages."""

from __future__ import annotations

from .collection_errors import COLLECTION_ERRORS, CollectionStatus, collection_status


def wandb_read_errors() -> tuple[type[Exception], ...]:
    try:
        from wandb.errors import CommError
    except ImportError:
        return COLLECTION_ERRORS
    return COLLECTION_ERRORS + (CommError,)


def wandb_read_status(exc: Exception) -> CollectionStatus:
    """Unwrap the SDK's explicit transport cause with a bounded walk."""
    try:
        from wandb.errors import AuthenticationError, CommError
    except ImportError:
        return collection_status(exc)
    for _ in range(4):
        status = collection_status(exc)
        if status != CollectionStatus.UNAVAILABLE:
            return status
        if isinstance(exc, AuthenticationError):
            return CollectionStatus.DENIED
        if not isinstance(exc, CommError) or not isinstance(exc.exc, Exception):
            break
        exc = exc.exc
    return CollectionStatus.UNAVAILABLE
