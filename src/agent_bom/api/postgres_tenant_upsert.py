"""Tenant-scoped upsert for rows keyed by a globally unique id.

`INSERT ... ON CONFLICT (id) DO UPDATE ... WHERE t.tenant_id = EXCLUDED.tenant_id`
used to update zero rows when the id belonged to another tenant. Since
PostgreSQL 16.16 (CVE-2026-120154) the server checks the conflicting row against
the UPDATE row-level security policies before that WHERE clause and raises
instead. The documented contract was always that an ON CONFLICT DO UPDATE never
silently skips a row the policies hide, so the old shape only worked by accident.

This never asks the server to update a row the session cannot see: insert with
DO NOTHING, otherwise update the caller's own row. If both touch nothing the id
exists in another tenant, unless the row was deleted in between, so the insert
is tried once more before reporting it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]*$")


class _Executes(Protocol):
    def execute(self, query: Any, params: Any = ...) -> Any: ...


def _identifier(name: str) -> str:
    # Table and column names come from the store code, never from a request;
    # refuse anything that is not a plain lower-case identifier all the same.
    if not _IDENTIFIER.match(name):
        raise ValueError(f"not a plain SQL identifier: {name!r}")
    return name


def write_tenant_row(
    conn: _Executes,
    *,
    table: str,
    key: str,
    tenant: str,
    row: Mapping[str, object],
    update: Sequence[str],
) -> bool:
    """Write ``row``, owned by ``row[tenant]``; return False if ``row[key]`` belongs to another tenant.

    ``row`` is the full insert in column order; ``update`` names the columns an
    existing row of the same tenant takes from it.
    """
    table, key, tenant = _identifier(table), _identifier(key), _identifier(tenant)
    columns = ", ".join(_identifier(column) for column in row)
    placeholders = ", ".join("%s" for _ in row)
    insert = f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) ON CONFLICT ({key}) DO NOTHING"  # nosec B608 - identifiers validated above, values bound
    assignments = ", ".join(f"{_identifier(column)} = %s" for column in update)
    statement = f"UPDATE {table} SET {assignments} WHERE {key} = %s AND {tenant} = %s"  # nosec B608 - identifiers validated above, values bound
    insert_params = tuple(row.values())
    update_params = (*(row[column] for column in update), row[key], row[tenant])
    for _attempt in range(2):
        if conn.execute(insert, insert_params).rowcount == 1:
            return True
        if conn.execute(statement, update_params).rowcount == 1:
            return True
    return False
