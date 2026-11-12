"""Agent architecture reads on a migration-owned Postgres schema with application-role RLS: same answer as SQLite, per tenant."""

from __future__ import annotations

from agent_bom.api.graph_agent_architecture import read_agent_architecture
from agent_bom.api.graph_store import SQLiteGraphStore
from tests.test_api_graph_agent_architecture import _graph
from tests.test_postgres_migrated_graph_parity import migrated_fresh_database  # noqa: F401
from tests.test_postgres_migrated_graph_parity import pytestmark as _migrated_postgres_pytestmark

pytestmark = _migrated_postgres_pytestmark

_FIXTURES = ("langgraph_supervisor", "crewai_hierarchical")


def _as_tenant(tenant: str, call):  # type: ignore[no-untyped-def]
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        return call()
    finally:
        reset_current_tenant(token)


def test_postgres_architecture_matches_sqlite_and_stays_in_its_tenant(migrated_fresh_database, tmp_path):  # noqa: F811
    from agent_bom.api.postgres_graph import PostgresGraphStore

    postgres = PostgresGraphStore()
    sqlite = SQLiteGraphStore(tmp_path / "graph.db")
    _as_tenant("acme", lambda: postgres.save_graph(_graph("acme", *_FIXTURES)))
    sqlite.save_graph(_graph("acme", *_FIXTURES))

    def read(store, tenant: str):  # type: ignore[no-untyped-def]
        return _as_tenant(tenant, lambda: read_agent_architecture(store, tenant_id=tenant, scan_id="harness-scan", offset=0, limit=50))

    expected = read(sqlite, "acme")
    assert expected["summary"]["harnesses"] == 2
    assert read(postgres, "acme") == expected
    other = read(postgres, "globex")
    assert other["harnesses"] == [] and other["summary"]["framework_agents"] == 0
