"""Real psycopg retention contract; connection mocks cannot prove cursor APIs."""

import os
from datetime import datetime, timedelta, timezone

import pytest

from tests.test_postgres_migrated_graph_parity import _with_database, migrated_fresh_database  # noqa: F401
from tests.test_postgres_migrated_graph_parity import pytestmark as pytestmark


def test_store_reset_reopens_wrapped_pool_and_keeps_retention_override(migrated_fresh_database, monkeypatch):  # noqa: F811
    from agent_bom.api import postgres_common, tenant_graph_retention_store
    from tests.conftest import _snapshot_store_singletons

    monkeypatch.setattr(tenant_graph_retention_store, "_tenant_graph_retention_store", None)
    token = postgres_common.set_current_tenant("retention-a")
    try:
        original = tenant_graph_retention_store._get_tenant_graph_retention_store()
        original.put("retention-a", 400)
        postgres_common.reset_pool()
        assert original._backend._pool.closed
        _snapshot_store_singletons()
        assert tenant_graph_retention_store._tenant_graph_retention_store is None
        restored = tenant_graph_retention_store._get_tenant_graph_retention_store()
        assert restored is not original
        assert restored.get("retention-a") == 400
        assert restored.get("retention-b") is None
    finally:
        postgres_common.reset_current_tenant(token)


@pytest.mark.parametrize("fail_cleanup", [False, True])
def test_save_purges_only_expired_owned_history_on_real_psycopg(migrated_fresh_database, monkeypatch, fail_cleanup):  # noqa: F811
    import psycopg

    from agent_bom.api import postgres_graph_snapshots
    from agent_bom.api.postgres_common import _tenant_connection, reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from scripts.profile_graph_snapshot_storage import _snapshot

    now = datetime.now(timezone.utc)
    store = PostgresGraphStore()
    for tenant in ("retention-a", "retention-b"):
        token = set_current_tenant(tenant)
        try:
            for index in range(3):
                store.save_graph(_snapshot(index, 3, now.isoformat(), tenant))
        finally:
            reset_current_tenant(token)
    admin = _with_database(os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"], migrated_fresh_database)
    with psycopg.connect(admin) as conn:
        conn.execute("UPDATE graph_snapshots SET created_at=%s WHERE scan_id='retained-0'", ((now - timedelta(days=400)).isoformat(),))
        conn.execute("UPDATE graph_snapshots SET created_at='unparseable' WHERE scan_id='retained-1'")
    token = set_current_tenant("retention-b")
    try:
        with _tenant_connection(store._pool) as conn:
            store._purge_expired_snapshots(conn, "retention-a")
    finally:
        reset_current_tenant(token)
    with psycopg.connect(admin) as conn:
        assert conn.execute("SELECT count(*) FROM graph_snapshots WHERE tenant_id='retention-a'").fetchone()[0] == 3
    if fail_cleanup:
        execute = postgres_graph_snapshots._execute_many_batched

        def fail_after_child_deletes(conn, statement, params, **kwargs):
            if statement.startswith("DELETE FROM graph_nodes "):
                raise RuntimeError("synthetic cleanup interruption")
            return execute(conn, statement, params, **kwargs)

        monkeypatch.setattr(postgres_graph_snapshots, "_execute_many_batched", fail_after_child_deletes)
    token = set_current_tenant("retention-a")
    try:
        store.save_graph(_snapshot(3, 3, now.isoformat(), "retention-a"))
        remaining = {row["scan_id"] for row in store.list_snapshots(tenant_id="retention-a")}
        assert remaining == (
            {"retained-0", "retained-1", "retained-2", "retained-3"} if fail_cleanup else {"retained-1", "retained-2", "retained-3"}
        )
        assert not store.load_graph(tenant_id="retention-b", scan_id="retained-0").nodes
    finally:
        reset_current_tenant(token)
    with psycopg.connect(admin) as conn:
        assert conn.execute("SELECT count(*) FROM graph_snapshots WHERE tenant_id='retention-b'").fetchone()[0] == 3
        assert conn.execute("SELECT count(*) FROM graph_nodes WHERE tenant_id='retention-a' AND scan_id='retained-0'").fetchone()[0] == (
            3 if fail_cleanup else 0
        )
        assert conn.execute("SELECT count(*) FROM graph_edges WHERE tenant_id='retention-a' AND scan_id='retained-0'").fetchone()[0] == (
            2 if fail_cleanup else 0
        )
        assert conn.execute("SELECT count(*) FROM graph_nodes WHERE tenant_id='retention-b' AND scan_id='retained-0'").fetchone()[0] == 3
