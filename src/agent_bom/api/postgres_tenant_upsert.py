"""Tenant-scoped upsert for rows keyed by a globally unique id.

`INSERT ... ON CONFLICT (id) DO UPDATE ... WHERE t.tenant_id = EXCLUDED.tenant_id`
used to update zero rows when the id belonged to another tenant. Since
PostgreSQL 16.16 (CVE-2026-120154) the server checks the conflicting row against
the UPDATE row-level security policies before that WHERE clause and raises
instead. The documented contract was always that an ON CONFLICT DO UPDATE never
silently skips a row the policies hide, so the old shape only worked by accident.

This never asks the server to update a row the session cannot see: update the
caller's own row, otherwise insert with DO NOTHING. If both touch nothing the id
exists in another tenant, unless a same-tenant writer inserted it in between, so
the update is tried once more before reporting it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from psycopg import sql


class _Executes(Protocol):
    def execute(self, query: Any, params: Any = ...) -> Any: ...


def write_tenant_row(
    conn: _Executes,
    *,
    table: str,
    key: tuple[str, object],
    tenant: tuple[str, object],
    values: Mapping[str, object],
    insert_only: Mapping[str, object] | None = None,
) -> bool:
    """Write one row owned by ``tenant``; return False if ``key`` belongs to another tenant.

    ``values`` are written on insert and update; ``insert_only`` only on insert.
    """
    key_column, key_value = key
    tenant_column, tenant_value = tenant
    update = sql.SQL("UPDATE {table} SET {assignments} WHERE {key} = %s AND {tenant} = %s").format(
        table=sql.Identifier(table),
        assignments=sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(column)) for column in values),
        key=sql.Identifier(key_column),
        tenant=sql.Identifier(tenant_column),
    )
    update_params = [*values.values(), key_value, tenant_value]
    inserted = {key_column: key_value, tenant_column: tenant_value, **(insert_only or {}), **values}
    insert = sql.SQL("INSERT INTO {table} ({columns}) VALUES ({placeholders}) ON CONFLICT ({key}) DO NOTHING").format(
        table=sql.Identifier(table),
        columns=sql.SQL(", ").join(sql.Identifier(column) for column in inserted),
        placeholders=sql.SQL(", ").join(sql.Placeholder() for _ in inserted),
        key=sql.Identifier(key_column),
    )
    for _attempt in range(2):
        if conn.execute(update, update_params).rowcount == 1:
            return True
        if conn.execute(insert, list(inserted.values())).rowcount == 1:
            return True
    return False
