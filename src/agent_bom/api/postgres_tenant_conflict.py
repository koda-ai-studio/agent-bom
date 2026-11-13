"""Report Postgres refusing an upsert onto another tenant's row as the store's own error."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

_RLS_USING_VIOLATION = "row-level security policy (USING expression)"


@contextmanager
def cross_tenant_conflict_as(message: str) -> Iterator[None]:
    """Raise ``ValueError(message)`` when RLS rejects the existing row of a tenant-guarded upsert.

    Tenant-guarded upserts filter a foreign row with ``ON CONFLICT ... WHERE``.
    Postgres can instead reject the existing row under its RLS ``USING`` check
    first. Either way the row is not touched; only this one error is
    translated, so other privilege failures still surface.
    """
    from psycopg.errors import InsufficientPrivilege

    try:
        yield
    except InsufficientPrivilege as exc:
        if _RLS_USING_VIOLATION not in str(exc):
            raise
        raise ValueError(message) from None
