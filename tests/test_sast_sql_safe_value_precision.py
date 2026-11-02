"""Precision of the SQL-construction rule for values that cannot carry input.

Every false-positive shape is lifted from agent-bom's own source, where the
dogfood scan reported it: a template whose only substitutions are literals or
constants, a local name only ever bound to literal SQL, a numeric coercion, a
loop over literal or constant collections, a list of literal clauses, psycopg
composition, and identifiers that pass an explicit validator. The paired
true-positive shapes keep the same syntax but let a parameter in.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.ast_analyzer import analyze_project


def _sql_findings(tmp_path: Path, source: str) -> list:
    (tmp_path / "store.py").write_text(source, encoding="utf-8")
    result = analyze_project(tmp_path)
    return [finding for finding in result.flow_findings if finding.category == "sql_string_construction"]


SAFE_SHAPES = {
    # api/fleet_store.py, api/access_review.py: constant template, literal or constant substitution.
    "constant-template-format": (
        '_CREATE_SQL = "CREATE TABLE IF NOT EXISTS {table} (id TEXT)"\n'
        '_MIGRATION_TABLE = "fleet_agents_migration"\n'
        "\n"
        "def init(conn):\n"
        '    conn.execute(_CREATE_SQL.format(table="fleet_agents"))\n'
        "    conn.execute(_CREATE_SQL.format(table=_MIGRATION_TABLE))\n"
    ),
    # intel_lookup.py: local literal template with a literal WHERE clause.
    "local-literal-template-format": (
        "def lookup(conn, raw_id):\n"
        '    base = """SELECT id FROM vulns v WHERE {where} ORDER BY id"""\n'
        '    return conn.execute(base.format(where="v.id = ?"), (raw_id,)).fetchall()\n'
    ),
    # api/postgres_graph_paths.py: literal SQL extended with literal fragments.
    "local-literal-augmented": (
        "def paths(conn, tenant_id, source_ids):\n"
        '    sql = "SELECT path_json FROM graph_attack_paths WHERE tenant_id = %s"\n'
        "    params = [tenant_id]\n"
        "    if source_ids is not None:\n"
        '        sql += " AND source_node = ANY(%s)"\n'
        "        params.append(sorted(source_ids))\n"
        '    return conn.execute(sql + " ORDER BY rank_index", params).fetchall()\n'
    ),
    # db/graph_store_snapshots.py: reviewed augmented fragments.
    "reviewed-augmented-fragment": (
        "def nodes(conn, tenant_id, entity_types, sev_sql):\n"
        '    query = "SELECT * FROM graph_nodes WHERE tenant_id = ?"\n'
        "    if entity_types:\n"
        '        placeholders = ",".join("?" * len(entity_types))\n'
        '        query += f" AND entity_type IN ({placeholders})"\n'
        "    if sev_sql:\n"
        '        query += f" AND {sev_sql}"  # nosec B608 - fragment is built from a static template\n'
        "    return conn.execute(query, [tenant_id])\n"
    ),
    # api/hub_observations_partition.py: a literal savepoint name.
    "local-literal-name": (
        "def create(conn, ddl):\n"
        '    savepoint = "agent_bom_observation_partition"\n'
        '    conn.execute(f"SAVEPOINT {savepoint}")\n'
        '    conn.execute(f"RELEASE SAVEPOINT {savepoint}")\n'
    ),
    # api/snowflake_store.py: reviewed assignment, then extended with literal SQL.
    "reviewed-assignment-then-extended": (
        "def summaries(cur, where, limit, params):\n"
        '    sql = f"SELECT job_id FROM scan_jobs{where} ORDER BY created_at DESC"  # nosec B608 - fixed fragments\n'
        "    if limit is not None:\n"
        '        sql = f"{sql} LIMIT %s OFFSET %s"\n'
        "    cur.execute(sql, tuple(params))\n"
    ),
    # storage/sqlite_wal.py: numeric coercion.
    "numeric-coercion": (
        "def restore(conn):\n"
        '    busy_timeout = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])\n'
        '    conn.execute(f"PRAGMA busy_timeout={busy_timeout}")\n'
    ),
    # api/trace_collection/writes.py: loop over a literal tuple of statements.
    "literal-loop-target": (
        "def write(tx, receipts, observations):\n"
        "    for rows, insert in (\n"
        '        (receipts, "INSERT INTO receipts(a,b) VALUES "),\n'
        '        (observations, "INSERT INTO observations(a,b) VALUES "),\n'
        "    ):\n"
        '        tx.execute(insert + ",".join("(?,?)" for _ in rows), tuple(rows))\n'
    ),
    # api/storage/compliance_snapshot.py: loop over a module constant mapping.
    "constant-collection-loop": (
        'COLUMNS = {"compliance_hub_findings": ("id",), "compliance_hub_ledger": ("ordinal",)}\n'
        "\n"
        "def read(conn):\n"
        "    for table, columns in COLUMNS.items():\n"
        '        conn.execute(f"PRAGMA table_info({table})")\n'
    ),
    # api/storage/finding_history_schema.py: literal loop values, method calls on them, reviewed join.
    "literal-loop-method-and-reviewed-join": (
        "def install(conn):\n"
        '    for event in ("INSERT", "UPDATE", "DELETE"):\n'
        '        statements = " ".join(\n'
        '            f"DELETE FROM {table} WHERE job_id=OLD.job_id;"  # nosec B608 - fixed trigger identifiers\n'
        '            for table in ("rows", "jobs")\n'
        "        )\n"
        '        conn.execute(f"CREATE TRIGGER t_{event.lower()} AFTER {event} ON jobs BEGIN {statements} END")\n'
    ),
    # api/postgres_job_store.py: a list that only ever holds literal clauses.
    "literal-clause-list-join": (
        "def summaries(conn, tenant_id, status, query):\n"
        '    base_sql = "SELECT job_id FROM scan_jobs"\n'
        "    clauses: list[str] = []\n"
        "    params = []\n"
        "    if tenant_id is not None:\n"
        '        clauses.append("team_id = %s")\n'
        "        params.append(tenant_id)\n"
        "    if query:\n"
        "        clauses.append(\n"
        '            "LOWER(job_id) "\n'
        "            \"LIKE %s ESCAPE '\\\\'\"\n"
        "        )\n"
        '    where = f" WHERE {\' AND \'.join(clauses)}" if clauses else ""\n'
        '    sql = f"{base_sql}{where} ORDER BY created_at DESC"\n'
        "    return conn.execute(sql, tuple(params)).fetchall()\n"
    ),
    # api/tenant_lifecycle.py: psycopg composition quotes the identifier itself.
    "psycopg-composition": (
        "from psycopg import sql\n"
        "\n"
        "def purge(conn, table, tenant_id):\n"
        '    conn.execute(sql.SQL("DELETE FROM {} WHERE tenant_id = %s").format(sql.Identifier(table)), (tenant_id,))\n'
    ),
    # cloud/clickhouse.py: a same-module validator called as a statement before use.
    "validator-statement": (
        "import re\n"
        '_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")\n'
        "\n"
        'def _validate_identifier(name, kind="identifier"):\n'
        "    if not _IDENTIFIER_RE.match(name):\n"
        '        raise ValueError("invalid")\n'
        "    return name\n"
        "\n"
        "class Client:\n"
        "    def ensure(self, database):\n"
        '        _validate_identifier(self.database, "database")\n'
        '        self.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")\n'
        "\n"
        "def columns(conn, table):\n"
        "    _validate_identifier(table)\n"
        '    return conn.execute(f"PRAGMA table_info({table})").fetchall()\n'
    ),
    # db/local_analytics_sqlite.py: an imported validator named for what it does.
    "imported-validator-statement": (
        "from agent_bom.db.sql_identifiers import validate_sql_identifier\n"
        "\n"
        "def columns(conn, table):\n"
        "    validate_sql_identifier(table)\n"
        '    scratch = f"{table}_rekey_migration"\n'
        '    conn.execute(f"DROP TABLE IF EXISTS {scratch}")\n'
        '    return conn.execute(f"PRAGMA table_info({table})").fetchall()\n'
    ),
    # export/destinations.py: every assignment of the attribute passes the validator.
    "validated-class-attribute": (
        "import re\n"
        '_WAREHOUSE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")\n'
        '_RUNS_SUFFIX = "_runs"\n'
        "\n"
        "def _warehouse_ident(value, *, field):\n"
        "    if not _WAREHOUSE_IDENT.fullmatch(value):\n"
        "        raise ValueError(field)\n"
        "    return value\n"
        "\n"
        "class Destination:\n"
        "    def __init__(self, client, table):\n"
        "        self._client = client\n"
        '        self._table = _warehouse_ident(table, field="table")\n'
        "\n"
        "    def write(self):\n"
        '        runs_table = f"{self._table}{_RUNS_SUFFIX}"\n'
        '        self._client.execute(f"CREATE TABLE IF NOT EXISTS {runs_table} (id String)")\n'
        "        self._client.execute(f\"DROP TABLE {_warehouse_ident(runs_table, field='x')}\")\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(SAFE_SHAPES))
def test_value_that_cannot_carry_input_is_not_reported(tmp_path: Path, shape: str) -> None:
    assert _sql_findings(tmp_path, SAFE_SHAPES[shape]) == []


UNSAFE_SHAPES = {
    "constant-template-formatted-with-parameter": (
        '_CREATE_SQL = "CREATE TABLE IF NOT EXISTS {table} (id TEXT)"\n'
        "\n"
        "def init(conn, name):\n"
        "    conn.execute(_CREATE_SQL.format(table=name))\n"
    ),
    "parameter-template-formatted-with-literal": ('def init(conn, template):\n    conn.execute(template.format(table="t"))\n'),
    "literal-augmented-with-input": (
        "def paths(conn, value):\n"
        '    sql = "SELECT a FROM t WHERE 1 = 1"\n'
        "    sql += f\" AND b = '{value}'\"\n"
        "    return conn.execute(sql)\n"
    ),
    "augmented-with-helper-fragment": (
        "def records(conn, tenant_id):\n"
        "    scope, params = _cost_scope(tenant_id)\n"
        '    sql = "SELECT a FROM llm_costs WHERE "\n'
        "    sql += scope\n"
        "    return conn.execute(sql, params)\n"
    ),
    "literal-name-rebound-to-input": (
        'def create(conn, raw):\n    savepoint = "sp"\n    savepoint = raw\n    conn.execute(f"SAVEPOINT {savepoint}")\n'
    ),
    "loop-over-parameter": ('def drop(conn, tables):\n    for table in tables:\n        conn.execute(f"DROP TABLE {table}")\n'),
    "loop-over-literal-and-input": (
        'def drop(conn, extra):\n    for table in ("a", extra):\n        conn.execute(f"DROP TABLE {table}")\n'
    ),
    "clause-list-appended-with-input": (
        "def summaries(conn, query):\n"
        "    clauses = []\n"
        "    clauses.append(f\"name = '{query}'\")\n"
        '    return conn.execute("SELECT 1 FROM t WHERE " + " AND ".join(clauses))\n'
    ),
    "clause-list-handed-to-helper": (
        "def summaries(conn, query):\n"
        "    clauses = []\n"
        "    add_filters(clauses, query)\n"
        '    return conn.execute("SELECT 1 FROM t WHERE " + " AND ".join(clauses))\n'
    ),
    "numeric-looking-but-not-coerced": ('def restore(conn, timeout):\n    conn.execute(f"PRAGMA busy_timeout={timeout}")\n'),
    "method-call-on-input": ('def lookup(conn, name):\n    conn.execute(f"SELECT 1 FROM {name.lower()}")\n'),
    "psycopg-sql-built-from-fstring": (
        'from psycopg import sql\n\ndef purge(conn, table):\n    conn.execute(sql.SQL(f"DELETE FROM {table}").format())\n'
    ),
    "used-before-validation": (
        "def _validate_identifier(name):\n"
        "    if not name.isidentifier():\n"
        '        raise ValueError("invalid")\n'
        "    return name\n"
        "\n"
        "def columns(conn, table):\n"
        '    conn.execute(f"PRAGMA table_info({table})")\n'
        "    _validate_identifier(table)\n"
    ),
    "validated-then-rebound": (
        "def _validate_identifier(name):\n"
        "    if not name.isidentifier():\n"
        '        raise ValueError("invalid")\n'
        "    return name\n"
        "\n"
        "def columns(conn, table, raw):\n"
        "    _validate_identifier(table)\n"
        "    table = raw\n"
        '    conn.execute(f"PRAGMA table_info({table})")\n'
    ),
    "pass-through-helper-is-not-a-validator": (
        'def _ident(value):\n    return value\n\ndef columns(conn, table):\n    conn.execute(f"PRAGMA table_info({_ident(table)})")\n'
    ),
    "class-attribute-with-an-unvalidated-assignment": (
        "def _warehouse_ident(value):\n"
        "    if not value.isidentifier():\n"
        '        raise ValueError("invalid")\n'
        "    return value\n"
        "\n"
        "class Destination:\n"
        "    def __init__(self, table):\n"
        "        self._table = _warehouse_ident(table)\n"
        "\n"
        "    def retarget(self, table):\n"
        "        self._table = table\n"
        "\n"
        "    def write(self, client):\n"
        '        client.execute(f"DROP TABLE {self._table}")\n'
    ),
}


@pytest.mark.parametrize("shape", sorted(UNSAFE_SHAPES))
def test_value_that_can_carry_input_is_still_reported(tmp_path: Path, shape: str) -> None:
    findings = _sql_findings(tmp_path, UNSAFE_SHAPES[shape])
    assert len(findings) >= 1, shape
    assert all(finding.title == "SQL query is built through string interpolation" for finding in findings)
