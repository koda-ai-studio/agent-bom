"""Borrowed-connection scope, connect kwargs and row-iteration helpers for Snowflake discovery."""

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Callable
from typing import Any

from agent_bom.security import sanitize_error

# A caller-owned Snowflake connection (e.g. a brokered read-only connection from
# a stored cloud connection) can be lent to the estate-sweep discovery helpers,
# which each open+close their own connection from env/args. When set, every
# ``_get_connection`` (and the two direct-connect discoverers) reuse this one
# connection instead of building one, and never close it — the borrower owns the
# lifecycle. Scoped via ``_borrowed_connection`` so it is per-call and never
# leaks across tenants/requests on a shared server.
_ACTIVE_CONNECTION: contextvars.ContextVar[Any | None] = contextvars.ContextVar("_sf_active_connection", default=None)


class _BorrowedConnection:
    """Proxy over a caller-owned Snowflake connection whose ``close`` is a no-op.

    Estate discovery helpers each ``conn.close()`` in a ``finally``. When they run
    against a lent (brokered) connection they must not close it — the borrower
    owns its lifecycle — so this proxy forwards every attribute to the real
    connection but swallows ``close``.
    """

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def close(self) -> None:  # noqa: D401 - lifecycle owned by the borrower
        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


@contextlib.contextmanager
def _borrowed_connection(conn: Any):
    """Lend ``conn`` to the estate discovery helpers for the duration of the block."""
    token = _ACTIVE_CONNECTION.set(conn)
    try:
        yield
    finally:
        _ACTIVE_CONNECTION.reset(token)


def _active_borrowed_connection() -> Any | None:
    """Return a non-closing proxy over the lent connection, or ``None`` if none is set."""
    active = _ACTIVE_CONNECTION.get()
    return _BorrowedConnection(active) if active is not None else None


def _base_connect_kwargs(
    account: str | None,
    user: str | None,
    authenticator: str | None,
    database: str | None,
    schema: str | None,
) -> dict[str, Any]:
    """Connector kwargs for *account*/*user* plus the optional authenticator/database/schema context.

    Callers resolve auth themselves (``_resolve_snowflake_auth``) so its deprecation
    warning keeps the same ``stacklevel`` attribution.
    """
    conn_kwargs: dict[str, Any] = {
        "account": account,
        "user": user,
    }
    if authenticator:
        conn_kwargs["authenticator"] = authenticator
    if database:
        conn_kwargs["database"] = database
    if schema:
        conn_kwargs["schema"] = schema
    return conn_kwargs


def _for_each_row(
    conn: Any,
    sql: str,
    handle: Callable[[dict[str, Any]], object],
    on_error: Callable[[Exception], object],
) -> None:
    """Run *sql* on its own cursor and feed each row (lower-cased column keys) to *handle*.

    A failure is handed to *on_error* so one query never aborts the discovery;
    the cursor is always closed.
    """
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            handle(dict(zip(keys, row)))
    except Exception as exc:  # noqa: BLE001
        on_error(exc)
    finally:
        cursor.close()


def _warn_with(warnings: list[str], prefix: str) -> Callable[[Exception], None]:
    """``on_error`` for :func:`_for_each_row` recording ``"<prefix>: <sanitized error>"``."""
    return lambda exc: warnings.append(f"{prefix}: {sanitize_error(exc)}")
