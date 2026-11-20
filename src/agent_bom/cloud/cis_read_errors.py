"""Bounded read-failure labels for CIS benchmark evidence.

Provider exception messages can carry account identifiers, resource paths or
request echoes, so CIS evidence names only the exception type and, when the SDK
exposes one, its short provider error code. Per-resource reads that fail for a
reason other than a permission denial are recorded under ``READ_FAILED`` so
``finalize_read_coverage`` reports ERROR instead of a PASS over unread resources.
"""

from __future__ import annotations

import re

from .aws_inv._base import _error_code, is_access_denied_error

READ_FAILED = "read_failed"

_CODE_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}")


def read_error_label(exc: BaseException) -> str:
    """Return ``ExceptionType`` or ``ExceptionType (ProviderCode)``; never the message.

    Permission failures are prefixed ``permission denied:`` so operators still
    see the actionable cause without the provider text.
    """
    name = type(exc).__name__
    code = _error_code(exc)
    label = f"{name} ({code})" if code and code != name and _CODE_TOKEN.fullmatch(code) else name
    return f"permission denied: {label}" if is_access_denied_error(exc) else label


def record_read_failure(unavailable: dict[str, list[str]], resource: str) -> None:
    """Record a resource whose read failed for a non-permission reason."""
    unavailable.setdefault(READ_FAILED, []).append(resource)
