"""Lazy GCP SDK exception boundaries and fixed, secret-free diagnostics."""

from __future__ import annotations

from contextlib import AbstractContextManager

from .collection_errors import COLLECTION_ERRORS, CollectionError, CollectionStatus, collection_status, collection_warning, isolated_record
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


def gcp_record(warnings: list[str], service: str) -> AbstractContextManager[None]:
    """Isolate one listed GCP record behind the fixed ``gcp_read_warning``."""
    return isolated_record(warnings, gcp_read_errors(), gcp_read_warning, service)


def text_attr(value: object, name: str) -> str:
    """Return a provider attribute only when it is a concrete string."""
    attr = getattr(value, name, "")
    return attr if isinstance(attr, str) else ""


def gcp_text(value: object, fallback: str) -> str:
    """An SDK string field: unset falls back, any non-string is a malformed record."""
    if value is None or value == "":
        return fallback
    if not isinstance(value, str):
        raise TypeError("Invalid GCP record field")
    return value
