"""Revision-cached snapshot stats on a migration-owned Postgres schema with application-role RLS."""

from __future__ import annotations

from tests.test_graph_snapshot_stats_cache import _graph
from tests.test_postgres_migrated_graph_parity import migrated_fresh_database  # noqa: F401
from tests.test_postgres_migrated_graph_parity import pytestmark as _migrated_postgres_pytestmark

pytestmark = _migrated_postgres_pytestmark


def _as_tenant(tenant: str, call):  # type: ignore[no-untyped-def]
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        return call()
    finally:
        reset_current_tenant(token)


def test_postgres_stats_follow_rewrites_and_tenants(migrated_fresh_database):  # noqa: F811
    from agent_bom.api.postgres_graph import PostgresGraphStore

    store = PostgresGraphStore()
    _as_tenant("acme", lambda: store.save_graph(_graph("acme", "scan-1", 3)))
    _as_tenant("globex", lambda: store.save_graph(_graph("globex", "scan-1", 7)))

    def stats(tenant: str, **filters):  # type: ignore[no-untyped-def]
        return _as_tenant(tenant, lambda: store.snapshot_stats(tenant_id=tenant, scan_id="scan-1", **filters))

    assert stats("acme")["relationship_types"] == {"depends_on": 3}
    assert stats("acme")["relationship_types"] == {"depends_on": 3}
    assert stats("globex")["relationship_types"] == {"depends_on": 7}
    assert stats("acme", entity_types={"package"})["total_nodes"] == 4

    _as_tenant("acme", lambda: store.save_graph(_graph("acme", "scan-1", 5)))

    assert stats("acme")["relationship_types"] == {"depends_on": 5}
    assert stats("acme", entity_types={"package"})["total_nodes"] == 6
    assert stats("globex")["relationship_types"] == {"depends_on": 7}
