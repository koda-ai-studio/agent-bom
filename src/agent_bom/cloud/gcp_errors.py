"""Lazy GCP SDK exception boundaries and fixed, secret-free diagnostics."""

from __future__ import annotations

from .collection_errors import COLLECTION_ERRORS, CollectionError, CollectionStatus, collection_status, collection_warning
from .normalization import ServiceNotInUse


def gcp_read_errors() -> tuple[type[Exception], ...]:
    """Keep SDK dependencies optional while catching their documented failures."""
    errors: tuple[type[Exception], ...] = COLLECTION_ERRORS + (ImportError,)
    try:
        from google.api_core.exceptions import GoogleAPIError
    except ImportError:
        pass
    else:
        errors += (GoogleAPIError,)
    try:
        from google.auth.exceptions import GoogleAuthError
    except ImportError:
        pass
    else:
        errors += (GoogleAuthError,)
    return errors


def gcp_read_status(exc: Exception) -> CollectionStatus:
    """Use structured HTTP codes; never inspect provider message text."""
    status = collection_status(exc)
    if status != CollectionStatus.UNAVAILABLE:
        return status
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        status = {401: CollectionStatus.DENIED, 403: CollectionStatus.DENIED, 429: CollectionStatus.THROTTLED}.get(
            code, CollectionStatus.UNAVAILABLE
        )
        if status != CollectionStatus.UNAVAILABLE:
            return status
    try:
        from google.auth.exceptions import DefaultCredentialsError, RefreshError
    except ImportError:
        pass
    else:
        if isinstance(exc, (DefaultCredentialsError, RefreshError)):
            return CollectionStatus.DENIED
    return CollectionStatus.UNAVAILABLE


def gcp_read_warning(service: str, exc: Exception) -> str:
    if getattr(exc, "reason", None) == "SERVICE_DISABLED":
        return ServiceNotInUse(f"{service} API is disabled; recorded as not in use.")
    return collection_warning("gcp", service, CollectionError(gcp_read_status(exc)))
