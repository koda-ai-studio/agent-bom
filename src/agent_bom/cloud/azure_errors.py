"""Lazy Azure SDK exception boundaries and fixed inventory diagnostics."""

from __future__ import annotations

from contextlib import AbstractContextManager

from .collection_errors import COLLECTION_ERRORS, CollectionError, CollectionStatus, collection_status, collection_warning, isolated_record


def azure_read_errors() -> tuple[type[Exception], ...]:
    """Keep optional Azure imports lazy; do not catch unrelated programming bugs."""
    try:
        from azure.core.exceptions import AzureError
    except ImportError:
        return (*COLLECTION_ERRORS, ImportError)
    return (*COLLECTION_ERRORS, ImportError, AzureError)


def azure_read_status(exc: Exception) -> CollectionStatus:
    """Use SDK types and HTTP status fields, never provider message contents."""
    status = collection_status(exc)
    if status is not CollectionStatus.UNAVAILABLE:
        return status
    code = getattr(exc, "status_code", None)
    if code in (401, 403):
        return CollectionStatus.DENIED
    if code == 429:
        return CollectionStatus.THROTTLED
    try:
        from azure.core.exceptions import ClientAuthenticationError
    except ImportError:
        return status
    return CollectionStatus.DENIED if isinstance(exc, ClientAuthenticationError) else status


def azure_read_warning(resource: str, exc: Exception) -> str:
    return collection_warning("azure", resource, CollectionError(azure_read_status(exc)))


def azure_record(warnings: list[str], resource: str) -> AbstractContextManager[None]:
    """Isolate one listed Azure record behind the fixed ``azure_read_warning``."""
    return isolated_record(warnings, azure_read_errors(), azure_read_warning, resource)


def azure_text(value: object, fallback: str) -> str:
    """An SDK string attribute: unset falls back, any non-string is a malformed record."""
    if value is None or value == "":
        return fallback
    if not isinstance(value, str):
        raise TypeError("Invalid Azure record field")
    return value
