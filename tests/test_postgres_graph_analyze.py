"""After a large snapshot save, the DML-only app role refreshes graph planner statistics through one narrow function.

Right after a 5,000-agent save ``graph_nodes`` and ``graph_edges`` had never
been analyzed and the explicit-scan graph reads planned without statistics
(586 ms median locally against 166 ms after ``ANALYZE``). The app role cannot
run ``ANALYZE`` itself; ``public.abom_analyze_graph_tables()`` is a
``SECURITY DEFINER`` function with no arguments that analyzes those two tables
and nothing else, executable only by the app role.

Live tier: needs ``AGENT_BOM_POSTGRES_ADMIN_URL`` and ``AGENT_BOM_POSTGRES_URL``.
"""

from __future__ import annotations

import os

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests.test_postgres_migrated_graph_parity import _with_database, migrated_fresh_database  # noqa: F401
from tests.test_postgres_migrated_graph_parity import pytestmark as pytestmark

TENANT = "analyze-tenant"
FUNCTION = "public.abom_analyze_graph_tables()"


def _admin(database: str):
    import psycopg

    return psycopg.connect(_with_database(os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"], database), autocommit=True)


def _app(database: str):
    """A connection as the app role, the way the API resolves its URL and password file."""
    import psycopg

    from agent_bom.api.postgres_common import resolve_postgres_secret, resolve_postgres_url

    url = resolve_postgres_url()
    assert url.rsplit("/", 1)[-1].split("?")[0] == database
    secret = resolve_postgres_secret()
    return psycopg.connect(url, autocommit=True, **({"password": secret} if secret else {}))


def _last_analyze(conn, table: str):
    return conn.execute("SELECT last_analyze FROM pg_stat_user_tables WHERE relname = %s", (table,)).fetchone()[0]


def _settle_stats(conn) -> None:
    # Cumulative statistics are flushed by backends lazily; force a fresh read.
    conn.execute("SELECT pg_stat_clear_snapshot()")


def _graph(nodes: int, scan: str = "analyze-scan") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan, tenant_id=TENANT, created_at="2026-11-14T00:00:00Z")
    for index in range(nodes):
        graph.add_node(UnifiedNode(id=f"package:p{index}", entity_type=EntityType.PACKAGE, label=f"p{index}"))
    for index in range(nodes - 1):
        graph.add_edge(UnifiedEdge(source=f"package:p{index}", target=f"package:p{index + 1}", relationship=RelationshipType.DEPENDS_ON))
    return graph


def _save(graph: UnifiedGraph) -> None:
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    token = set_current_tenant(TENANT)
    try:
        PostgresGraphStore().save_graph(graph)
    finally:
        reset_current_tenant(token)


def test_the_app_role_cannot_analyze_directly_but_can_call_the_function(migrated_fresh_database) -> None:  # noqa: F811
    with _admin(migrated_fresh_database) as admin:
        assert admin.execute("SELECT has_function_privilege('public', %s, 'EXECUTE')", (FUNCTION,)).fetchone()[0] is False
        assert admin.execute("SELECT has_function_privilege('agent_bom_app', %s, 'EXECUTE')", (FUNCTION,)).fetchone()[0] is True
        prosecdef, config = admin.execute("SELECT prosecdef, proconfig FROM pg_proc WHERE oid = %s::regprocedure", (FUNCTION,)).fetchone()
        assert prosecdef is True
        assert any(item.startswith("search_path=") for item in config or []), "search_path is pinned"
        assert admin.execute("SELECT pg_get_function_arguments(%s::regprocedure)", (FUNCTION,)).fetchone()[0] == ""
    with _app(migrated_fresh_database) as app:
        app.execute("ANALYZE public.graph_nodes")  # PostgreSQL skips it with a warning for a non-owner
        _settle_stats(app)
        assert _last_analyze(app, "graph_nodes") is None, "the app role analyzed a table it does not own"
        analyzed = app.execute(f"SELECT {FUNCTION}").fetchone()[0]
        assert analyzed == 2
        _settle_stats(app)
        assert _last_analyze(app, "graph_nodes") is not None
        assert _last_analyze(app, "graph_edges") is not None


def test_the_function_analyzes_nothing_but_the_two_graph_tables(migrated_fresh_database) -> None:  # noqa: F811
    with _admin(migrated_fresh_database) as admin:
        before = dict(admin.execute("SELECT relname, last_analyze FROM pg_stat_user_tables").fetchall())
    with _app(migrated_fresh_database) as app:
        app.execute(f"SELECT {FUNCTION}")
    with _admin(migrated_fresh_database) as admin:
        admin.execute("SELECT pg_stat_clear_snapshot()")
        after = dict(admin.execute("SELECT relname, last_analyze FROM pg_stat_user_tables").fetchall())
    changed = {table for table in after if after[table] != before.get(table)}
    assert changed == {"graph_nodes", "graph_edges"}


def test_a_repeat_call_inside_the_cooldown_does_no_work(migrated_fresh_database) -> None:  # noqa: F811
    with _app(migrated_fresh_database) as app:
        assert app.execute(f"SELECT {FUNCTION}").fetchone()[0] == 2
        assert app.execute(f"SELECT {FUNCTION}").fetchone()[0] == 0


def test_a_large_save_leaves_the_graph_tables_analyzed_and_planned_with_statistics(migrated_fresh_database, monkeypatch) -> None:  # noqa: F811
    from agent_bom.api import postgres_graph_analyze

    monkeypatch.setattr(postgres_graph_analyze, "ANALYZE_AFTER_ROWS", 2_000)
    _save(_graph(1_500))
    with _admin(migrated_fresh_database) as admin:
        admin.execute("SELECT pg_stat_clear_snapshot()")
        assert _last_analyze(admin, "graph_nodes") is not None
        assert _last_analyze(admin, "graph_edges") is not None
        reltuples = admin.execute("SELECT reltuples FROM pg_class WHERE oid = 'public.graph_nodes'::regclass").fetchone()[0]
        assert reltuples >= 1_400, "the planner still has no row estimate for graph_nodes"
        plan = admin.execute(
            "EXPLAIN (FORMAT JSON) SELECT * FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s", (TENANT, "analyze-scan")
        ).fetchone()[0]
        assert plan[0]["Plan"]["Plan Rows"] >= 1_000, plan


def test_a_small_save_does_not_analyze(migrated_fresh_database, monkeypatch) -> None:  # noqa: F811
    from agent_bom.api import postgres_graph_analyze

    monkeypatch.setattr(postgres_graph_analyze, "ANALYZE_AFTER_ROWS", 2_000)
    _save(_graph(10))
    with _admin(migrated_fresh_database) as admin:
        admin.execute("SELECT pg_stat_clear_snapshot()")
        assert _last_analyze(admin, "graph_nodes") is None


def test_a_missing_function_never_fails_the_save(migrated_fresh_database, monkeypatch, caplog) -> None:  # noqa: F811
    from agent_bom.api import postgres_graph_analyze

    monkeypatch.setattr(postgres_graph_analyze, "ANALYZE_AFTER_ROWS", 2)
    with _admin(migrated_fresh_database) as admin:
        admin.execute(f"DROP FUNCTION {FUNCTION}")
    _save(_graph(5, scan="still-saved"))
    with _admin(migrated_fresh_database) as admin:
        admin.execute("SELECT set_config('app.bypass_rls', '1', false)")
        assert admin.execute("SELECT count(*) FROM graph_nodes WHERE scan_id = 'still-saved'").fetchone()[0] == 5
    assert "planner statistics" in caplog.text


def test_the_migration_downgrade_removes_only_the_function(migrated_fresh_database) -> None:  # noqa: F811
    from alembic import command
    from alembic.config import Config

    from tests.test_postgres_migrated_graph_parity import ALEMBIC_DIR, _sqlalchemy_url

    cfg = Config(str(ALEMBIC_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR / "alembic"))
    admin_url = _with_database(os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"], migrated_fresh_database)
    os.environ["ALEMBIC_DATABASE_URL"] = _sqlalchemy_url(admin_url)
    command.downgrade(cfg, "20261113_01")
    with _admin(migrated_fresh_database) as admin:
        assert admin.execute("SELECT to_regprocedure(%s)", (FUNCTION,)).fetchone()[0] is None
        assert admin.execute("SELECT to_regclass('public.graph_nodes')").fetchone()[0] is not None
    command.upgrade(cfg, "head")
    with _admin(migrated_fresh_database) as admin:
        assert admin.execute("SELECT to_regprocedure(%s)", (FUNCTION,)).fetchone()[0] is not None


@pytest.mark.parametrize("table", ["graph_nodes", "graph_edges"])
def test_the_function_body_names_only_fixed_tables(table) -> None:
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1] / "deploy/supabase/postgres/alembic/versions/20261114_01_graph_analyze_function.py"
    ).read_text(encoding="utf-8")
    assert f"ANALYZE public.{table}" in source
    assert "EXECUTE format" not in source and "EXECUTE '" not in source.split("$analyze$", 2)[1], "no dynamic SQL in the body"
