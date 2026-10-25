"""Tenant-key invariant: one tenant can never overwrite, shadow or collide with another tenant's row.

Every table that holds per-tenant rows (a ``tenant_id`` or ``team_id`` column)
must carry the tenant in its primary key and in every unique constraint. The
only exceptions are listed in ``GLOBAL_KEYS`` with the reason the key is safe
to be global: an id minted server-side at random (never caller-chosen), an id
derived from the tenant itself, a database-minted surrogate, or a key that is
global on purpose. A caller-supplied or deterministic id under a global key is
the defect this guard exists to catch.

Coverage:
- SQLite: every ``*SQLite*`` store class is instantiated on a temporary
  database, so runtime re-key migrations are included; ``CREATE TABLE``
  literals in modules no store instantiates are checked statically.
- Postgres: the live, migrated schema (runs in CI's real Postgres step).
- ClickHouse: every ``ReplacingMergeTree`` with a tenant column dedups by a
  sort key that starts with the tenant.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import os
import pkgutil
import re
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "agent_bom"
TENANT_COLUMNS = ("tenant_id", "team_id")

_UUID4 = "uuid4 minted server-side at create; never caller-chosen"
_RANDOM = "secrets.token_hex minted server-side at create; never caller-chosen"
_SURROGATE = "database-minted sequence surrogate"
_NO_WRITER = "legacy init.sql table with no writer in the codebase"

GLOBAL_KEYS: dict[tuple[str, tuple[str, ...]], str] = {
    # Global on purpose.
    ("agent_identities", ("token_hash",)): "token resolution happens before the tenant is known; a hash must name one identity",
    ("model_virtual_keys", ("token_hash",)): "bearer digest: the same secret must never authenticate as two principals",
    ("managed_trial_invitations", ("token_digest",)): "bearer digest: one invitation per secret",
    ("agent_identity_jit_grants", ("grant_id",)): "global by design: put_jit_grant refuses another tenant's id (takeover guard)",
    ("agent_conditional_access_policies", ("policy_id",)): "global by design: put refuses another tenant's id (takeover guard)",
    ("teams", ("slug",)): "team slugs are the global routing namespace",
    # Ids derived from the tenant.
    ("hitl_approvals", ("item_id",)): "sha256(tenant_id:span_id) (hitl_item_id)",
    ("side_scan_execution_state", ("execution_id",)): "uuid5 over tenant/provider/account/target/idempotency scope",
    ("policy_audit_log", ("entry_id",)): "uuid4 per entry; Postgres trigger derives the physical key from the tenant",
    # Ids minted server-side at random.
    ("audit_log", ("entry_id",)): _UUID4,
    ("cloud_connections", ("id",)): _UUID4 + "; demo ids embed the tenant (_tenant_scoped_id)",
    ("credential_refs", ("credential_ref_id",)): _UUID4,
    ("exceptions", ("exception_id",)): "exc-<uuid4> minted in VulnException.__post_init__",
    ("export_destinations", ("id",)): _UUID4,
    ("export_schedules", ("schedule_id",)): _UUID4,
    ("issue_mappings", ("mapping_id",)): _UUID4,
    ("mcp_client_configs", ("config_id",)): _RANDOM,
    ("model_provider_keys", ("provider_key_id",)): _RANDOM,
    ("model_virtual_keys", ("virtual_key_id",)): _RANDOM,
    ("gateway_policies", ("policy_id",)): _UUID4 + "; quarantine ids are uuid5 over the tenant",
    ("proxy_replay_log", ("row_id",)): _UUID4,
    ("scan_schedules", ("schedule_id",)): _UUID4,
    ("sources", ("source_id",)): _UUID4 + "; demo ids embed the tenant (_tenant_scoped_id)",
    ("control_plane_sources", ("source_id",)): _UUID4 + "; demo ids embed the tenant (_tenant_scoped_id)",
    ("webhook_subscriptions", ("subscription_id",)): _RANDOM,
    ("ticketing_connections", ("id",)): _UUID4,
    ("ticket_links", ("id",)): _UUID4,
    ("api_keys", ("key_id",)): _RANDOM,
    ("managed_trial_invitations", ("invitation_id",)): _RANDOM,
    # Database surrogates (Postgres; SQLite INTEGER rowid keys are recognised automatically).
    ("cis_benchmark_checks", ("id",)): _SURROGATE,
    ("governance_audit_log", ("seq",)): _SURROGATE,
    ("policy_audit_log", ("id",)): _SURROGATE,
    ("trend_history", ("id",)): _SURROGATE,
    # Legacy Postgres tables nothing writes.
    ("agents", ("agent_id",)): _NO_WRITER,
    ("findings", ("finding_id",)): _NO_WRITER,
    ("policy_results", ("result_id",)): _NO_WRITER,
    ("job_queue", ("job_id",)): _NO_WRITER,
    # Not a tenant boundary.
    ("scan_runs", ("run_id",)): "operator-local CLI history mirror (one OS user, raw-SQL query access); not a tenant store",
}

_SQLITE_PACKAGES = (
    "agent_bom",
    "agent_bom.api",
    "agent_bom.db",
    "agent_bom.ticketing",
    "agent_bom.cloud",
    "agent_bom.runtime",
    "agent_bom.graph",
    "agent_bom.connectors",
    "agent_bom.storage",
)
_NOT_SQLITE = re.compile(r"postgres|clickhouse|snowflake|neptune|databricks|__main__|\.cli\b|\.cli\.")


# ── checkers ────────────────────────────────────────────────────────────────


def sqlite_violations(conn: sqlite3.Connection) -> list[tuple[str, tuple[str, ...]]]:
    """``(table, key columns)`` for every tenant table whose key or unique constraint omits the tenant."""
    violations: list[tuple[str, tuple[str, ...]]] = []
    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"):
        info = conn.execute(f"PRAGMA table_info('{table}')").fetchall()
        tenant = next((c for c in TENANT_COLUMNS if c in {row[1] for row in info}), None)
        if tenant is None:
            continue
        pk_rows = sorted((row for row in info if row[5]), key=lambda row: row[5])
        pk = tuple(str(row[1]) for row in pk_rows)
        rowid_surrogate = len(pk_rows) == 1 and str(pk_rows[0][2]).upper() == "INTEGER"
        keys = [] if rowid_surrogate or not pk else [pk]
        for index in conn.execute(f"PRAGMA index_list('{table}')").fetchall():
            if index[2] and index[3] != "pk":
                keys.append(tuple(str(row[2]) for row in conn.execute(f"PRAGMA index_info('{index[1]}')")))
        violations.extend((table, key) for key in keys if tenant not in key)
    return violations


def postgres_violations(conn, schema: str = "public") -> list[tuple[str, tuple[str, ...]]]:
    rows = conn.execute(
        """
        SELECT t.relname, ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(attnum, n)
                                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum ORDER BY k.n)
        FROM pg_index i
        JOIN pg_class t ON t.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE i.indisunique AND n.nspname = %s AND t.relkind IN ('r', 'p')
          AND EXISTS (SELECT 1 FROM information_schema.columns c
                      WHERE c.table_schema = n.nspname AND c.table_name = t.relname AND c.column_name = ANY(%s))
          AND NOT EXISTS (SELECT 1 FROM pg_inherits h WHERE h.inhrelid = t.oid)
        """,
        (schema, list(TENANT_COLUMNS)),
    ).fetchall()
    return [(table, tuple(columns)) for table, columns in rows if not set(columns) & set(TENANT_COLUMNS)]


def unexplained(violations: list[tuple[str, tuple[str, ...]]]) -> list[tuple[str, tuple[str, ...]]]:
    return sorted({violation for violation in violations if violation not in GLOBAL_KEYS})


# ── SQLite discovery ────────────────────────────────────────────────────────


def _sqlite_store_classes() -> list[type]:
    names: set[str] = set()
    for package_name in _SQLITE_PACKAGES:
        package = importlib.import_module(package_name)
        if package_name == "agent_bom":
            names.update(f"agent_bom.{info.name}" for info in pkgutil.iter_modules(package.__path__) if not info.ispkg)
        else:
            names.update(info.name for info in pkgutil.walk_packages(package.__path__, f"{package_name}."))
    classes: dict[str, type] = {}
    for name in sorted(names):
        if _NOT_SQLITE.search(name):
            continue
        try:
            module = importlib.import_module(name)
        except Exception:  # noqa: BLE001 - an optional extra this CI job does not install
            continue
        for class_name, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ == name and "sqlite" in class_name.lower() and not inspect.isabstract(cls):
                classes.setdefault(f"{name}.{class_name}", cls)
    return list(classes.values())


def _instantiate(cls: type, path: Path) -> bool:
    for call in (lambda: cls(str(path)), lambda: cls(db_path=str(path))):
        try:
            store = call()
        except TypeError:
            continue
        except Exception:  # noqa: BLE001 - not a path-constructed store (abstract adapter, helper)
            return False
        if callable(getattr(store, "save_graph", None)):
            from agent_bom.graph import UnifiedGraph

            store.save_graph(UnifiedGraph(tenant_id="tenant-key-invariant", scan_id="schema-probe"))  # the graph schema is created lazily
        return True
    return False


@pytest.fixture(scope="module")
def instantiated(tmp_path_factory) -> tuple[dict[str, list[tuple[str, tuple[str, ...]]]], set[str]]:
    root = tmp_path_factory.mktemp("tenant-key-invariant")
    found: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
    tables: set[str] = set()
    for cls in _sqlite_store_classes():
        path = root / f"{cls.__module__}.{cls.__name__}.db"
        if not _instantiate(cls, path) or not path.exists():
            continue
        with sqlite3.connect(path) as conn:
            found[f"{cls.__module__}.{cls.__name__}"] = sqlite_violations(conn)
            tables.update(row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'"))
    return found, tables


def test_every_instantiated_sqlite_store_keys_tenant_rows_by_tenant(instantiated):
    found, tables = instantiated
    assert len(found) >= 40, f"store discovery went vacuous: only {len(found)} SQLite stores instantiated"
    assert {"agent_identities", "access_review_campaigns", "jobs", "fleet_agents", "graph_nodes", "cloud_connections"} <= tables
    bad = {store: unexplained(violations) for store, violations in found.items() if unexplained(violations)}
    assert bad == {}, "tenant rows keyed without the tenant (fix the key, or justify it in GLOBAL_KEYS)"


def _ddl_literals() -> list[tuple[str, str, str]]:
    """``(location, table, statement)`` for every literal SQLite ``CREATE TABLE`` with a fixed name."""
    literals: list[tuple[str, str, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        if _NOT_SQLITE.search(str(path.relative_to(ROOT)).replace("/", ".")):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            for match in re.finditer(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(", node.value, re.IGNORECASE):
                depth, end = 0, None
                for offset, char in enumerate(node.value[match.end() - 1 :]):
                    depth += char == "("
                    depth -= char == ")"
                    if depth == 0:
                        end = match.end() + offset
                        break
                if end is not None:
                    literals.append((f"{path.relative_to(ROOT)}:{node.lineno}", match.group(1), node.value[match.start() : end]))
    return literals


def test_sqlite_ddl_no_store_instantiates_still_keys_tenant_rows_by_tenant(instantiated):
    _found, tables = instantiated
    checked, bad = 0, []
    for location, table, statement in _ddl_literals():
        if table in tables:
            continue
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute(statement)
        except sqlite3.Error:
            continue  # Postgres dialect or a fragment, owned by the Postgres check
        checked += 1
        bad.extend((location, violation) for violation in unexplained(sqlite_violations(conn)))
    assert checked >= 5, "static DDL discovery went vacuous"
    assert bad == []


# ── red fixtures: the guard provably fails on a bad table ───────────────────


def test_the_sqlite_checker_flags_a_global_key_on_tenant_rows():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE bad_widgets (widget_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, data TEXT)")
    conn.execute("CREATE TABLE bad_slugs (tenant_id TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, id INTEGER PRIMARY KEY AUTOINCREMENT)")
    conn.execute("CREATE TABLE good_widgets (tenant_id TEXT NOT NULL, widget_id TEXT NOT NULL, PRIMARY KEY (tenant_id, widget_id))")
    conn.execute("CREATE TABLE good_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, UNIQUE (tenant_id, seq))")
    assert unexplained(sqlite_violations(conn)) == [("bad_slugs", ("slug",)), ("bad_widgets", ("widget_id",))]


def test_an_allowlist_entry_covers_only_its_own_table_and_columns():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE cloud_connections (name TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)")
    assert unexplained(sqlite_violations(conn)) == [("cloud_connections", ("name",))]


def test_every_allowlist_entry_has_a_reason():
    assert all(reason.strip() for reason in GLOBAL_KEYS.values())


# ── ClickHouse ──────────────────────────────────────────────────────────────


def _clickhouse_ddl() -> list[str]:
    from agent_bom.cloud.clickhouse import _TABLE_DDL

    init_sql = (ROOT / "deploy" / "supabase" / "clickhouse" / "init.sql").read_text(encoding="utf-8")
    return [*_TABLE_DDL, *re.findall(r"CREATE TABLE IF NOT EXISTS.*?;", init_sql, re.S)]


def clickhouse_violations(statements: list[str]) -> list[str]:
    bad = []
    for statement in statements:
        table = re.search(r"CREATE TABLE IF NOT EXISTS\s+(\w+)", statement)
        order = re.search(r"ORDER BY\s+\(?([^)\n;]*)", statement)
        if not table or "ReplacingMergeTree" not in statement or not re.search(r"\btenant_id\b", statement.split("ENGINE")[0]):
            continue
        if not order or order.group(1).split(",")[0].strip() != "tenant_id":
            bad.append(table.group(1))
    return bad


def test_clickhouse_replacing_tables_dedup_within_a_tenant():
    statements = _clickhouse_ddl()
    assert len(statements) >= 10
    assert clickhouse_violations(statements) == []
    bad = (
        "CREATE TABLE IF NOT EXISTS widgets (\n    tenant_id String,\n    id String\n) "
        "ENGINE = ReplacingMergeTree(updated_at)\nORDER BY (id)"
    )
    assert clickhouse_violations([bad]) == ["widgets"]


# ── Postgres (CI's real Postgres storage contract step) ─────────────────────

_POSTGRES_URL = os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL") or ""


@pytest.mark.skipif(not (os.environ.get("AGENT_BOM_POSTGRES_URL") and _POSTGRES_URL), reason="needs the migrated Postgres cluster")
def test_every_migrated_postgres_tenant_table_keys_by_tenant():
    import psycopg

    with psycopg.connect(_POSTGRES_URL) as conn:
        violations = postgres_violations(conn)
        assert len({table for table, _ in violations}) >= 10, "Postgres catalog discovery went vacuous"
        assert unexplained(violations) == []
        conn.execute("CREATE TEMP TABLE bad_widgets (widget_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)")
        conn.execute(
            "CREATE TEMP TABLE good_widgets (tenant_id TEXT NOT NULL, widget_id TEXT NOT NULL, PRIMARY KEY (tenant_id, widget_id))"
        )
        temp_schema = conn.execute("SELECT nspname FROM pg_namespace WHERE oid = pg_my_temp_schema()").fetchone()[0]
        assert unexplained(postgres_violations(conn, temp_schema)) == [("bad_widgets", ("widget_id",))]
