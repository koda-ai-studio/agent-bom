"""Every Postgres table and column a store creates at runtime is migration-owned.

Postgres stores still carry ``CREATE TABLE IF NOT EXISTS`` / ``ADD COLUMN``
bootstrap DDL for unconfigured development pools, but on a configured
deployment ``ensure_postgres_schema_version`` returns False and Alembic is the
only thing that creates schema. A table or column that exists only in store
code therefore works in every unit test and fails with ``UndefinedTable`` /
``UndefinedColumn`` on a migrated database.

This guard discovers the runtime DDL itself (no hand-kept file list): every
string literal in ``src/agent_bom`` that creates a table or adds a column,
inside a module that talks to Postgres, minus code scoped to another engine.
The authority is what an *upgraded* deployment has executed: every Alembic
revision, the ``agent_bom`` modules those revisions import their DDL from, and
``init.sql`` / ``runtime-schema.sql`` only as they stood when ``20260718_01``
last replayed them (``fixtures/postgres_schema_replayed_20260718.json``).
Revisions ``20260416_01`` and ``20260718_01`` read those files at upgrade time,
so a later edit to either reaches fresh installs but never a database already
past them; such a change needs its own additive revision.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
POSTGRES_DIR = ROOT / "deploy" / "supabase" / "postgres"
VERSIONS = POSTGRES_DIR / "alembic" / "versions"
REPLAYED_SNAPSHOT = ROOT / "tests" / "fixtures" / "postgres_schema_replayed_20260718.json"

_IDENT = r'"?([A-Za-z_][A-Za-z0-9_]*)"?'
_QUALIFIED = rf"(?:{_IDENT}\s*\.\s*)?{_IDENT}"
_CREATE_TABLE = re.compile(
    rf"\bCREATE\s+(?:(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP|TEMPORARY|UNLOGGED)\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{_QUALIFIED}\s*(\(|PARTITION\s+OF|AS\b)",
    re.IGNORECASE,
)
_ALTER_TABLE = re.compile(rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{_QUALIFIED}", re.IGNORECASE)
_ADD_COLUMN = re.compile(rf"\bADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?{_IDENT}", re.IGNORECASE)
_CONSTRAINT_KEYWORDS = frozenset({"primary", "foreign", "unique", "constraint", "check", "exclude", "like"})
# Modules that never reach Postgres even though they hold DDL for another engine.
_OTHER_ENGINE = re.compile(r"sqlite|snowflake|clickhouse|duckdb", re.IGNORECASE)
_SQLITE_ONLY_TOKENS = re.compile(r"\bAUTOINCREMENT\b|\bWITHOUT\s+ROWID\b|\bPRAGMA\b", re.IGNORECASE)
_POSTGRES_IMPORTS = re.compile(r"psycopg|postgres", re.IGNORECASE)

# Tables that store code creates on Postgres but no migration owns, each with
# the reason it is intentionally runtime-only. Keep this empty unless a table
# is genuinely ephemeral; a durable table gets an Alembic revision instead.
RUNTIME_ONLY_TABLES: dict[str, str] = {}


def strip_sql_comments(sql: str) -> str:
    """Drop ``--`` and ``/* */`` comments outside single-quoted literals.

    Column comments such as ``-- scrypt(raw_key, salt) hex`` hold commas and
    parentheses that would otherwise split one column definition into several.
    """
    out: list[str] = []
    index, length, in_quote = 0, len(sql), False
    while index < length:
        char = sql[index]
        if in_quote:
            out.append(char)
            in_quote = char != "'"
            index += 1
        elif char == "'":
            in_quote = True
            out.append(char)
            index += 1
        elif sql.startswith("--", index):
            newline = sql.find("\n", index)
            index = length if newline == -1 else newline
        elif sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = length if end == -1 else end + 2
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _split_top_level(body: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth, in_quote = 0, False
    for char in body:
        if in_quote:
            in_quote = char != "'"
        elif char == "'":
            in_quote = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _paren_body(sql: str, open_index: int) -> str:
    depth, cursor, in_quote = 1, open_index + 1, False
    while cursor < len(sql) and depth:
        char = sql[cursor]
        if in_quote:
            in_quote = char != "'"
        elif char == "'":
            in_quote = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        cursor += 1
    return sql[open_index + 1 : cursor - 1]


def ddl_columns(sql: str) -> dict[str, set[str]]:
    """Map each table a DDL text creates or alters to the columns it defines."""
    sql = strip_sql_comments(sql)
    tables: dict[str, set[str]] = {}
    for match in _CREATE_TABLE.finditer(sql):
        columns = tables.setdefault(match.group(2).lower(), set())
        if match.group(3) != "(":
            continue
        for part in _split_top_level(_paren_body(sql, match.end(3) - 1)):
            name = part.split()[0].strip('"').lower()
            if name not in _CONSTRAINT_KEYWORDS:
                columns.add(name)
    for match in _ALTER_TABLE.finditer(sql):
        end = sql.find(";", match.end())
        statement = sql[match.end() : len(sql) if end == -1 else end]
        nested = _ALTER_TABLE.search(statement)
        if nested:
            statement = statement[: nested.start()]
        added = {column.lower() for column in _ADD_COLUMN.findall(statement)}
        if added:
            tables.setdefault(match.group(2).lower(), set()).update(added)
    return tables


def _migration_imports() -> list[tuple[str, str]]:
    """``(module, name)`` pairs Alembic revisions import from ``agent_bom``."""
    pairs: set[tuple[str, str]] = set()
    for revision in sorted(VERSIONS.glob("*.py")):
        for node in ast.walk(ast.parse(revision.read_text())):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("agent_bom."):
                pairs.update((node.module, alias.name) for alias in node.names)
    return sorted(pairs)


def _migration_imported_ddl() -> list[str]:
    """DDL text revisions execute from ``agent_bom`` modules.

    Imported string constants count as-is, and zero-argument ``*ddl*`` builders
    (``registry_migration_ddl``) are called, since their table names are
    generated. Helpers that need a connection fall back to every literal in
    their module.
    """
    texts: list[str] = []
    for module_name, name in _migration_imports():
        module = importlib.import_module(module_name)
        value = getattr(module, name)
        if callable(value) and "ddl" in name.lower() and not _required_parameters(value):
            value = value()
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
            texts.extend(value)
        else:
            texts.extend(_string_literals(Path(inspect.getfile(module)).read_text()))
    return texts


def _required_parameters(function: object) -> list[str]:
    parameters = inspect.signature(function).parameters.values()  # type: ignore[arg-type]
    return [p.name for p in parameters if p.default is p.empty and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]


def migration_authority() -> dict[str, set[str]]:
    """Tables and columns every upgraded database is guaranteed to have."""
    replayed = json.loads(REPLAYED_SNAPSHOT.read_text())["tables"]
    merged: dict[str, set[str]] = {table: set(columns) for table, columns in replayed.items()}
    texts = [literal for path in sorted(VERSIONS.glob("*.py")) for literal in _string_literals(path.read_text())]
    for text in [*texts, *_migration_imported_ddl()]:
        for table, columns in ddl_columns(text).items():
            merged.setdefault(table, set()).update(columns)
    return merged


def _literal_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(str(part.value) if isinstance(part, ast.Constant) else "{dynamic}" for part in node.values)
    return None


def _string_literals(source: str) -> list[str]:
    return [text for node in ast.walk(ast.parse(source)) if (text := _literal_text(node)) is not None]


@dataclass(frozen=True)
class RuntimeDDL:
    location: str
    table: str
    columns: frozenset[str]


class _DDLCollector(ast.NodeVisitor):
    """Collect DDL literals with the class/function/assignment names that scope them."""

    def __init__(self) -> None:
        self.scope: list[str] = []
        self.found: list[tuple[str, str, int]] = []

    def _scoped(self, name: str, node: ast.AST) -> None:
        self.scope.append(name)
        super().generic_visit(node)
        self.scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scoped(node.name, node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scoped(node.name, node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scoped(node.name, node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._scoped(" ".join(target.id for target in node.targets if isinstance(target, ast.Name)), node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._scoped(node.target.id if isinstance(node.target, ast.Name) else "", node)

    def generic_visit(self, node: ast.AST) -> None:
        text = _literal_text(node)
        if text is not None:
            self.found.append((" ".join(self.scope), text, getattr(node, "lineno", 0)))
            return
        super().generic_visit(node)


def reaches_postgres(path: Path, tree: ast.Module) -> bool:
    """A module is Postgres-capable when named for it, importing it, or defining a ``Postgres*`` store."""
    if "postgres" in path.stem.lower():
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(_POSTGRES_IMPORTS.search(alias.name) for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and _POSTGRES_IMPORTS.search(
            " ".join([node.module or "", *(alias.name for alias in node.names)])
        ):
            return True
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and "postgres" in node.name.lower():
            return True
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and "postgres" in t.id.lower() for t in node.targets):
            return True
    return False


def runtime_postgres_ddl(paths: list[Path] | None = None, *, root: Path = ROOT) -> list[RuntimeDDL]:
    """Runtime DDL that can execute against Postgres, discovered from source."""
    found: list[RuntimeDDL] = []
    for path in paths if paths is not None else sorted((SRC / "agent_bom").rglob("*.py")):
        source = path.read_text()
        if not re.search(r"CREATE\s+(?:\w+\s+)?TABLE|ADD\s+COLUMN", source, re.IGNORECASE):
            continue
        tree = ast.parse(source)
        if _OTHER_ENGINE.search(path.stem) or not reaches_postgres(path, tree):
            continue
        collector = _DDLCollector()
        collector.visit(tree)
        for scope, text, line in collector.found:
            if _OTHER_ENGINE.search(scope) or _SQLITE_ONLY_TOKENS.search(text):
                continue
            for table, columns in ddl_columns(text).items():
                found.append(RuntimeDDL(f"{path.relative_to(root)}:{line}", table, frozenset(columns)))
    return found


def schema_gaps(runtime: list[RuntimeDDL], authority: dict[str, set[str]]) -> list[str]:
    gaps: list[str] = []
    for ddl in runtime:
        if ddl.table in RUNTIME_ONLY_TABLES:
            continue
        if ddl.table not in authority:
            gaps.append(f"{ddl.location}: table {ddl.table} has no migration")
            continue
        missing = sorted(ddl.columns - authority[ddl.table])
        if missing:
            gaps.append(f"{ddl.location}: {ddl.table} columns without a migration: {', '.join(missing)}")
    return sorted(set(gaps))


def test_every_runtime_postgres_table_and_column_is_migration_owned() -> None:
    runtime = runtime_postgres_ddl()
    assert len({ddl.table for ddl in runtime}) > 75, "runtime DDL discovery found too little; the guard would pass vacuously"
    assert schema_gaps(runtime, migration_authority()) == []


def test_fresh_install_schema_files_add_nothing_upgrades_miss() -> None:
    """``init.sql`` / ``runtime-schema.sql`` edits after the last replay need a revision."""
    authority = migration_authority()
    drift: list[str] = []
    for path in (POSTGRES_DIR / "init.sql", POSTGRES_DIR / "runtime-schema.sql"):
        for table, columns in ddl_columns(path.read_text()).items():
            if table not in authority:
                drift.append(f"{path.name}: table {table} has no revision")
            elif missing := sorted(columns - authority[table]):
                drift.append(f"{path.name}: {table} columns without a revision: {', '.join(missing)}")
    assert drift == []


def test_allowlisted_runtime_only_tables_are_still_created_at_runtime() -> None:
    created = {ddl.table for ddl in runtime_postgres_ddl()}
    assert sorted(set(RUNTIME_ONLY_TABLES) - created) == []
    assert all(reason.strip() for reason in RUNTIME_ONLY_TABLES.values())


def test_authority_reads_qualified_commented_and_imported_ddl() -> None:
    authority = migration_authority()
    # init.sql documents api_keys columns with comments that contain commas.
    assert {"key_salt", "key_prefix", "team_id", "last_used"} <= authority["api_keys"]
    # 20261027_03 alters ``public.drift_incidents``.
    assert "blueprint_key" in authority["drift_incidents"]
    # 20260929_01 executes INGEST_STATE_DDL imported from the store module.
    assert "hub_ledger_ingest_state" in authority


def test_parser_handles_multi_column_alters_and_dollar_quoted_blocks() -> None:
    sql = """
        DO $$ BEGIN
          ALTER TABLE public.widgets ADD COLUMN IF NOT EXISTS a TEXT, ADD COLUMN b INT;
        END $$;
        CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY, -- (comma, paren)
            note TEXT DEFAULT 'x -- not a comment', CONSTRAINT widgets_pk UNIQUE (id));
        CREATE TABLE widgets_2026 PARTITION OF widgets FOR VALUES IN ('a');
    """
    assert ddl_columns(sql) == {"widgets": {"id", "note", "a", "b"}, "widgets_2026": set()}


def test_new_runtime_table_or_column_without_a_migration_fails(tmp_path: Path) -> None:
    module = tmp_path / "postgres_widgets.py"
    module.write_text(
        "from agent_bom.api.postgres_common import _get_pool\n"
        "class PostgresWidgetStore:\n"
        "    def _init(self, conn):\n"
        '        conn.execute("CREATE TABLE IF NOT EXISTS widget_ledger (widget_id TEXT PRIMARY KEY)")\n'
        '        conn.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS widget_hint TEXT")\n'
        "class SQLiteWidgetStore:\n"
        "    def _init(self, conn):\n"
        '        conn.execute("CREATE TABLE IF NOT EXISTS sqlite_only_widgets (id TEXT)")\n'
    )
    gaps = schema_gaps(runtime_postgres_ddl([module], root=tmp_path), migration_authority())
    assert gaps == [
        "postgres_widgets.py:4: table widget_ledger has no migration",
        "postgres_widgets.py:5: api_keys columns without a migration: widget_hint",
    ]


@pytest.mark.parametrize("name", ["sqlite_cache.py", "clickhouse_sink.py"])
def test_other_engine_modules_are_not_postgres_runtime_ddl(tmp_path: Path, name: str) -> None:
    module = tmp_path / name
    module.write_text('import psycopg\nDDL = "CREATE TABLE IF NOT EXISTS engine_local (id TEXT)"\n')
    assert runtime_postgres_ddl([module], root=tmp_path) == []
