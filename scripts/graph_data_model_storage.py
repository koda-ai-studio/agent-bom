"""Persistence-layer ERD pages for the graph data-model generator.

Reads every ``CREATE TABLE`` and ``ALTER TABLE`` (added columns, primary and
foreign keys) from the deployment schema (Postgres bootstrap SQL and Alembic
revisions, ClickHouse and Snowflake SQL) and from string literals in
``src/agent_bom`` (static AST scan; nothing is imported, so no API framework or
database driver is loaded). Renders one Mermaid ``erDiagram`` per storage domain
plus a complete table index.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from collections import defaultdict
from pathlib import Path

INDEX_DOC = "docs/graph/data-model/storage-erd.md"
DOMAIN_DOC_DIR = "docs/graph/data-model/storage-erd"

# Modules whose CREATE TABLE text is not agent-bom's own persistence.
EXCLUDED_MODULES: dict[str, str] = {
    "src/agent_bom/export/destinations.py": "creates tables in a customer-owned export destination, not in agent-bom's store",
    "src/agent_bom/api/partition_maintenance.py": "generic partition builders; the parent tables are defined by their owning stores",
}

# Deployment schema sources with a fixed dialect. Postgres DDL here is the
# authoritative control-plane schema (bootstrap SQL plus Alembic revisions).
_FIXED_DIALECT: dict[str, str] = {
    "deploy/supabase/postgres/init.sql": "postgres",
    "deploy/supabase/postgres/runtime-schema.sql": "postgres",
    "deploy/supabase/postgres/alembic/versions/": "postgres",
    "deploy/supabase/clickhouse/init.sql": "clickhouse",
    "deploy/snowflake/setup.sql": "snowflake",
    "deploy/snowflake/native-app/dcm/V001__core_schema.sql": "snowflake",
    "deploy/snowflake/native-app/dcm/V003__fleet_endpoints.sql": "snowflake",
}

# Storage domains in display order: (key, title, exact table names, name prefixes),
# names space-separated.
# An exact name wins over a prefix; among prefixes the longest wins. A table that
# matches nothing fails generation, so a new table has to be placed on purpose.
_DOMAIN_SPECS: tuple[tuple[str, str, str, str], ...] = (
    (
        "tenancy",
        "Tenancy, identity and access",
        (
            "teams api_keys auth_session_attempts revoked_session_nonces credential_refs idempotency_keys "
            "model_provider_keys model_virtual_keys tenant_score_config_overrides"
        ),
        ("managed_trial_ agent_bom_tenant_ tenant_ api_rate_limit scim_ access_review_ agent_identit agent_conditional_"),
    ),
    (
        "scans",
        "Scans, jobs and reports",
        "jobs report_jobs side_scan_execution_state skills_scan_run mcp_scan_results job_queue",
        "scan_ job_overview_",
    ),
    (
        "inventory",
        "Inventory and assets",
        (
            "assets agents device_posture endpoint_devices endpoint_agent_bindings mcp_client_configs "
            "mcp_observations agent_lifecycle_records agent_bom_snapshots kspm_cluster_posture dataset_versions "
            "scan_packages"
        ),
        "fleet_ ai_system_blueprint",
    ),
    (
        "findings",
        "Findings, triage and VEX",
        (
            "findings scan_findings exceptions drift_incidents issue_mappings ticket_links hitl_approvals "
            "hub_cve_intel hub_ledger_ingest_state hub_overview_revisions campaign_evidence_state "
            "risk_campaign_workflows trend_history vulnerability_scans"
        ),
        "findings_ finding_history_ hub_findings_ compliance_hub_findings",
    ),
    (
        "graph",
        "Graph nodes, edges, snapshots and attack paths",
        "attack_paths interaction_risks merged_nodes",
        "graph_ edge_ node_ ws_",
    ),
    (
        "runtime",
        "Runtime, gateway and traces",
        "proxy_replay_log policy_audit_log posture_scores",
        "runtime_ gateway_ trace_collection_ llm_cost",
    ),
    (
        "compliance",
        "Compliance, audit and evidence",
        (
            "compliance_controls cis_benchmark_checks hub_framework_refs governance_audit_log policy_results "
            "evaluation_runs attestation_replay"
        ),
        "audit_",
    ),
    (
        "connectors",
        "Connectors, delivery and schedules",
        (
            "cloud_connections control_plane_sources sources ticketing_connections endpoint_connections "
            "endpoint_syncs endpoint_sync_events webhook_subscriptions posture_webhook_outbox "
            "delta_stream_watermarks bound_references"
        ),
        "export_ delivery_",
    ),
    (
        "vulndb",
        "Vulnerability intelligence (local database)",
        "vulns affected cpe_matches epss_scores kev_entries sync_meta osv_cache",
        "",
    ),
    (
        "other",
        "Schema metadata and maintenance",
        (
            "schema_version graph_schema_version graph_retention_state control_plane_schema_versions "
            "local_schema_meta agent_bom_hub_backfills fleet_agents_tenant_key_migration "
            "compliance_hub_findings_v2 adoption_events"
        ),
        "",
    ),
)
DOMAINS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = tuple(
    (key, title, tuple(exact.split()), tuple(prefixes.split())) for key, title, exact, prefixes in _DOMAIN_SPECS
)

TENANT_COLUMNS = ("tenant_id", "team_id")
# Key names too generic to imply a join unless both tables share a name stem.
GENERIC_KEYS = frozenset({"run_id", "event_id", "item_id", "row_id", "entry_id", "version_id", "result_id", "source_id"})

DIALECT_ORDER = ("postgres", "sqlite", "snowflake", "clickhouse")
DIALECT_LABEL = {
    "postgres": "Postgres",
    "sqlite": "SQLite",
    "snowflake": "Snowflake",
    "clickhouse": "ClickHouse",
}

_CREATE = re.compile(
    r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TRANSIENT\s+|TEMP(?:ORARY)?\s+|UNLOGGED\s+|HYBRID\s+)?TABLE\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>[^\s(;]+)(?=\s*\()",
    re.IGNORECASE,
)
_ALTER = re.compile(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?P<table>[\w.\"]+)", re.IGNORECASE)
_ADD_COLUMN = re.compile(r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<column>\w+)", re.IGNORECASE)
_ADD_FK = re.compile(r"FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+([\w.\"]+)\s*\(([^)]*)\)", re.IGNORECASE)
_ADD_PK = re.compile(r"ADD\s+CONSTRAINT\s+\w+\s+PRIMARY\s+KEY\s*\(([^)]*)\)", re.IGNORECASE)
_DDL_HINT = re.compile(r"CREATE\s+(?:\w+\s+)*TABLE|ADD\s+COLUMN|FOREIGN\s+KEY", re.IGNORECASE)
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_PG_MARKERS = re.compile(r"\b(JSONB|TIMESTAMPTZ|BIGSERIAL|SERIAL|BYTEA|PARTITION\s+BY|DOUBLE\s+PRECISION|UUID)\b|::|public\.", re.I)
_SQLITE_MARKERS = re.compile(r"\bAUTOINCREMENT\b|\bWITHOUT\s+ROWID\b|\bSTRICT\b", re.I)
_SNOWFLAKE_MARKERS = re.compile(r"\b(VARIANT|TIMESTAMP_NTZ|TIMESTAMP_LTZ|TIMESTAMP_TZ)\b", re.I)
_CONSTRAINT_HEADS = ("PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT", "CHECK", "INDEX", "PROJECTION", "EXCLUDE", "PERIOD")


@dataclasses.dataclass
class TableDef:
    name: str
    dialect: str
    module: str
    columns: list[str]
    primary_key: list[str]
    foreign_keys: list[tuple[str, str, str]]  # (column, ref_table, ref_column)
    partitioned: bool = False
    types: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Table:
    name: str
    defs: list[TableDef]
    domain: str = ""

    @property
    def primary(self) -> TableDef:
        return min(self.defs, key=lambda d: (DIALECT_ORDER.index(d.dialect), d.module))

    def columns(self, dialect: str | None = None) -> list[str]:
        seen: dict[str, None] = {}
        for d in sorted(self.defs, key=lambda d: (DIALECT_ORDER.index(d.dialect), d.module)):
            if dialect is None or d.dialect == dialect:
                seen.update(dict.fromkeys(d.columns))
        return list(seen)

    @property
    def primary_key(self) -> list[str]:
        return self.primary.primary_key or next((d.primary_key for d in self.defs if d.primary_key), [])

    @property
    def foreign_keys(self) -> list[tuple[str, str, str]]:
        return sorted({fk for d in self.defs for fk in d.foreign_keys})

    @property
    def dialects(self) -> list[str]:
        return sorted({d.dialect for d in self.defs}, key=DIALECT_ORDER.index)

    @property
    def modules(self) -> list[str]:
        return sorted({d.module for d in self.defs})


class DDLError(SystemExit):
    pass


# ── extraction ─────────────────────────────────────────────────────────────────


def _strip_sql_comments(sql: str) -> str:
    return re.sub(r"--[^\n]*", "", sql)


def _balanced(text: str) -> tuple[str, str]:
    """Split ``(body) trailer`` at the matching close paren."""
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[1:i], text[i + 1 :]
    return text[1:], ""


def _split_top(body: str) -> list[str]:
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(body):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(body[start:i])
            start = i + 1
    parts.append(body[start:])
    return [p.strip() for p in parts if p.strip()]


def _clean_ident(name: str) -> str:
    name = name.strip().strip('`"').strip()
    if "." in name:
        name = name.rsplit(".", 1)[1].strip('`"')
    return name.lower()


def _cols(text: str) -> list[str]:
    return [_clean_ident(c.split()[0]) for c in text.split(",") if c.strip()]


def _parse_body(body: str) -> tuple[list[str], list[str], list[tuple[str, str, str]], dict[str, str]]:
    columns: list[str] = []
    types: dict[str, str] = {}
    pk: list[str] = []
    fks: list[tuple[str, str, str]] = []
    for item in _split_top(body):
        head = item.split(None, 1)[0].upper()
        if head in _CONSTRAINT_HEADS:
            upper = item.upper()
            if "PRIMARY KEY" in upper:
                m = re.search(r"PRIMARY\s+KEY\s*\(([^)]*)\)", item, re.I)
                if m:
                    pk = _cols(m.group(1))
            m = re.search(r"FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+([\w.\"]+)\s*\(([^)]*)\)", item, re.I)
            if m:
                for col, ref_col in zip(_cols(m.group(1)), _cols(m.group(3)), strict=False):
                    fks.append((col, _clean_ident(m.group(2)), ref_col))
            continue
        name = _clean_ident(item.split(None, 1)[0])
        if not _IDENT.match(name):
            continue
        columns.append(name)
        type_match = re.match(r"\S+\s+([A-Za-z]\w*)", item)
        types[name] = type_match.group(1).lower() if type_match else "text"
        if re.search(r"\bPRIMARY\s+KEY\b", item, re.I) and not pk:
            pk = [name]
        m = re.search(r"\bREFERENCES\s+([\w.\"]+)\s*(?:\(([^)]*)\))?", item, re.I)
        if m:
            fks.append((name, _clean_ident(m.group(1)), _cols(m.group(2))[0] if m.group(2) else "id"))
    return columns, pk, fks, types


def _dialect(module: str, scope: str, sql: str, has_sqlite_import: bool) -> str:
    hint = f"{module} {scope}".lower()
    if "clickhouse" in hint or re.search(r"\bENGINE\s*=", sql, re.I):
        return "clickhouse"
    if "snowflake" in hint or _SNOWFLAKE_MARKERS.search(sql):
        return "snowflake"
    if "sqlite" in hint or _SQLITE_MARKERS.search(sql):
        return "sqlite"
    if "postgres" in hint or re.search(r"(^|[_/])pg[_.]", hint) or _PG_MARKERS.search(sql):
        return "postgres"
    return "sqlite" if has_sqlite_import else "postgres"


def _string_value(node: ast.AST, consts: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                expr = value.value
                if isinstance(expr, ast.Name) and expr.id in consts:
                    parts.append(consts[expr.id])
                else:
                    parts.append("{" + ast.unparse(expr) + "}")
        return "".join(parts)
    return None


def _module_consts(tree: ast.Module) -> dict[str, str]:
    consts: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                consts.update({t.id: value.value for t in targets if isinstance(t, ast.Name)})
    return consts


def _module_dicts(tree: ast.Module) -> dict[str, dict[str, str]]:
    dicts: dict[str, dict[str, str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            try:
                value = ast.literal_eval(node.value)
            except ValueError:
                continue
            if all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
                dicts.update({t.id: value for t in node.targets if isinstance(t, ast.Name)})
    return dicts


def _format_targets(nodes: list[ast.AST], consts: dict[str, str]) -> dict[str, set[str]]:
    """``TEMPLATE.format(table=…)`` call sites: template constant name -> table names."""
    found: dict[str, set[str]] = defaultdict(set)
    for node in nodes:
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        for kw in node.keywords:
            if kw.arg == "table":
                value = _string_value(kw.value, consts)
                if value is None and isinstance(kw.value, ast.Name):
                    value = consts.get(kw.value.id)
                if value:
                    found[node.func.value.id].add(value)
    return found


def _init_defaults(cls: ast.ClassDef | None) -> dict[str, str]:
    if cls is None:
        return {}
    for item in cls.body:
        if isinstance(item, ast.FunctionDef) and item.name == "__init__":
            args = item.args.args + item.args.kwonlyargs
            defaults = [None] * (len(item.args.args) - len(item.args.defaults)) + list(item.args.defaults)
            defaults += list(item.args.kw_defaults)
            return {
                a.arg: d.value for a, d in zip(args, defaults, strict=False) if isinstance(d, ast.Constant) and isinstance(d.value, str)
            }
    return {}


def _enclosing(node: ast.AST, parents: dict[ast.AST, ast.AST], kind: type) -> ast.AST | None:
    cur = parents.get(node)
    while cur is not None and not isinstance(cur, kind):
        cur = parents.get(cur)
    return cur


def _docstrings(tree: ast.Module) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _expand(sql: str, ctx: _ModuleContext, node: ast.AST) -> list[str]:
    """Resolve ``{placeholder}`` table names; raise when one cannot be resolved."""
    match = next((m for m in _CREATE.finditer(sql) if "{" in m.group("name")), None)
    if not match or re.match(r"\s*PARTITION\s+OF", sql[match.end("name") :], re.I):
        return [sql]
    placeholder = match.group("name").split("{", 1)[1].rstrip("}").rstrip('`"')
    names: set[str] = set()
    dict_ref = re.search(r"\{(\w+)\[" + re.escape(placeholder) + r"\]\}", sql)
    if dict_ref and dict_ref.group(1) in ctx.dicts:
        return [
            sql.replace("{" + placeholder + "}", key).replace(dict_ref.group(0), value)
            for key, value in sorted(ctx.dicts[dict_ref.group(1)].items())
        ]
    if placeholder.startswith("self."):
        cls = _enclosing(node, ctx.parents, ast.ClassDef)
        default = _init_defaults(cls if isinstance(cls, ast.ClassDef) else None).get(placeholder[5:])
        if default:
            names.add(default)
    template = _enclosing_assign_name(node, ctx.parents)
    if template and template in ctx.format_targets:
        names.update(ctx.format_targets[template])
    if not names:
        raise DDLError(f"{ctx.module}: cannot resolve table name {{{placeholder}}}; extend {__name__}._expand")
    return [sql.replace("{" + placeholder + "}", name) for name in sorted(names)]


def _enclosing_assign_name(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    parent = parents.get(node)
    if isinstance(parent, ast.Assign):
        return next((t.id for t in parent.targets if isinstance(t, ast.Name)), None)
    return None


@dataclasses.dataclass
class _ModuleContext:
    module: str
    consts: dict[str, str]
    dicts: dict[str, dict[str, str]]
    parents: dict[ast.AST, ast.AST]
    format_targets: dict[str, set[str]]
    has_sqlite: bool


def _scope_name(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    names = []
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            names.append(cur.name)
        cur = parents.get(cur)
    return " ".join(names)


def _alter_statements(sql: str) -> list[tuple[str, str]]:
    found = []
    for m in _ALTER.finditer(sql):
        end = sql.find(";", m.end())
        found.append((m.group("table"), sql[m.end() : end if end >= 0 else len(sql)]))
    return found


def _collect_sql(sql: str, module: str, dialect: str, defs: list[TableDef], added: list[_Added]) -> None:
    sql = _strip_sql_comments(sql)
    for raw_table, body in _alter_statements(sql):
        table = _clean_ident(raw_table)
        if not _IDENT.match(table):
            continue
        for m in _ADD_COLUMN.finditer(body):
            added.append(_Added(table, m.group("column").lower(), dialect, module))
        for m in _ADD_PK.finditer(body):
            added.append(_Added(table, "", dialect, module, primary_key=tuple(_cols(m.group(1)))))
        for m in _ADD_FK.finditer(body):
            for col, ref_col in zip(_cols(m.group(1)), _cols(m.group(3)), strict=False):
                added.append(_Added(table, "", dialect, module, (col, _clean_ident(m.group(2)), ref_col)))
    for match in _CREATE.finditer(sql):
        if re.match(r"\s*PARTITION\s+OF", sql[match.end("name") :], re.I):
            continue
        name = _clean_ident(match.group("name"))
        if not _IDENT.match(name):
            raise DDLError(f"{module}: unparseable table name {match.group('name')!r}")
        body, trailer = _balanced(sql[match.end("name") :].lstrip())
        columns, pk, fks, types = _parse_body(body)
        if not columns:
            continue
        trailer = trailer.split(";", 1)[0]
        if not pk:
            key = re.search(r"\b(?:PRIMARY\s+KEY|ORDER\s+BY)\s*\(?([\w\s,]+)\)?", trailer, re.I)
            if key:
                pk = [c for c in _cols(key.group(1)) if c in columns]
        partitioned = bool(re.search(r"PARTITION\s+BY", trailer, re.I))
        defs.append(TableDef(name, dialect, module, columns, pk, fks, partitioned, types))


@dataclasses.dataclass(frozen=True)
class _Added:
    table: str
    column: str
    dialect: str
    module: str
    foreign_key: tuple[str, str, str] | None = None
    primary_key: tuple[str, ...] = ()


def _python_units(path: Path, module: str) -> list[tuple[str, str]]:
    """``(sql, dialect)`` for every DDL-bearing string literal in a Python module."""
    text = path.read_text(encoding="utf-8")
    if not _DDL_HINT.search(text):
        return []
    tree = ast.parse(text, filename=str(path))
    nodes = list(ast.walk(tree))
    consts = _module_consts(tree)
    ctx = _ModuleContext(
        module,
        consts,
        _module_dicts(tree),
        {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)},
        _format_targets(nodes, consts),
        "sqlite3" in text,
    )
    skip = _docstrings(tree)
    units = []
    for node in nodes:
        if id(node) in skip or isinstance(ctx.parents.get(node), ast.JoinedStr):
            continue
        raw = _string_value(node, consts)
        if not raw or not _DDL_HINT.search(raw):
            continue
        scope = _scope_name(node, ctx.parents)
        fixed = _FIXED_DIALECT.get(module.split("/versions/")[0] + "/versions/") if "/versions/" in module else None
        for sql in _expand(raw, ctx, node):
            units.append((sql, fixed or _dialect(module, scope, sql, ctx.has_sqlite)))
    return units


def _source_files(root: Path) -> list[Path]:
    files = [p for p in (root / "src" / "agent_bom").rglob("*.py") if "__pycache__" not in p.parts]
    for pattern in _FIXED_DIALECT:
        files += root.glob(pattern + "*.py") if pattern.endswith("/") else root.glob(pattern)
    return sorted(set(files))


def extract_tables(root: Path) -> dict[str, Table]:
    defs: list[TableDef] = []
    added: list[_Added] = []
    for path in _source_files(root):
        module = path.relative_to(root).as_posix()
        if module in EXCLUDED_MODULES:
            continue
        if path.suffix == ".sql":
            _collect_sql(path.read_text(encoding="utf-8"), module, _FIXED_DIALECT[module], defs, added)
            continue
        for sql, dialect in _python_units(path, module):
            _collect_sql(sql, module, dialect, defs, added)
    tables: dict[str, Table] = {}
    for d in defs:
        tables.setdefault(d.name, Table(d.name, [])).defs.append(d)
    for item in added:
        if item.table not in tables:
            continue
        candidates = tables[item.table].defs
        targets = [d for d in candidates if d.dialect == item.dialect] or [d for d in candidates if d.module == item.module]
        for target in targets:
            if item.primary_key:
                target.primary_key = list(item.primary_key)
            elif item.foreign_key and item.foreign_key not in target.foreign_keys:
                target.foreign_keys.append(item.foreign_key)
            elif item.column and item.column not in target.columns:
                target.columns.append(item.column)
    return dict(sorted(tables.items()))


# ── domains and relations ──────────────────────────────────────────────────────


def domain_for(table: str) -> str:
    for key, _title, exact, _prefixes in DOMAINS:
        if table in exact:
            return key
    matches = [(len(prefix), key) for key, _t, _e, prefixes in DOMAINS for prefix in prefixes if table.startswith(prefix)]
    if not matches:
        raise DDLError(f"table {table!r} has no storage domain; add it to DOMAINS in {__name__}")
    return max(matches)[1]


def assign_domains(tables: dict[str, Table]) -> dict[str, Table]:
    for table in tables.values():
        table.domain = domain_for(table.name)
    return tables


@dataclasses.dataclass(frozen=True, order=True)
class Relation:
    parent: str
    child: str
    column: str
    parent_column: str
    kind: str  # "fk" | "logical"


def _is_identity_column(column: str) -> bool:
    return column in {"canonical_id", "stable_id"} or column.endswith(("_canonical_id", "_stable_id"))


def _families(table: Table) -> set[str]:
    return {d if d in ("clickhouse", "snowflake") else "relational" for d in table.dialects}


def join_key_owners(members: list[Table]) -> tuple[dict[str, tuple[str, str]], dict[str, list[str]]]:
    """Within one domain: column name -> (owning table, owning column), plus ambiguous keys.

    A declared foreign key names its owner directly. Otherwise a table owns a
    column when that column is its whole primary key apart from the tenant column.
    Tenant columns and the generic ``id`` never become join keys.
    """
    names = {t.name for t in members}
    owners: dict[str, tuple[str, str]] = {}
    for table in members:
        for column, ref_table, ref_column in table.foreign_keys:
            if column not in TENANT_COLUMNS and ref_table in names:
                owners.setdefault(column, (ref_table, ref_column))
    candidates: dict[str, set[str]] = defaultdict(set)
    for table in members:
        key = [c for c in table.primary_key if c not in TENANT_COLUMNS]
        if len(key) == 1 and key[0] != "id" and key[0].endswith("_id"):
            candidates[key[0]].add(table.name)
    ambiguous: dict[str, list[str]] = {}
    for column, owning in sorted(candidates.items()):
        if column in owners:
            continue
        if len(owning) == 1:
            owners[column] = (next(iter(owning)), column)
        else:
            ambiguous[column] = sorted(owning)
    return owners, ambiguous


def _members(tables: dict[str, Table], domain: str) -> list[Table]:
    return [t for _n, t in sorted(tables.items()) if t.domain == domain]


def relations(tables: dict[str, Table]) -> list[Relation]:
    """Declared foreign keys anywhere, plus same-domain logical joins on shared key columns."""
    found: set[Relation] = set()
    for table in tables.values():
        for column, ref_table, ref_column in table.foreign_keys:
            if ref_table in tables:
                found.add(Relation(ref_table, table.name, column, ref_column, "fk"))
    for domain, _title, _e, _p in DOMAINS:
        members = _members(tables, domain)
        owners, _ambiguous = join_key_owners(members)
        for table in members:
            declared = {fk[0] for fk in table.foreign_keys}
            for column in table.columns():
                if column in declared or column not in owners:
                    continue
                owner, owner_column = owners[column]
                if owner == table.name or not _families(tables[owner]) & _families(table):
                    continue
                if column in GENERIC_KEYS and owner.split("_", 1)[0] != table.name.split("_", 1)[0]:
                    continue
                found.add(Relation(owner, table.name, column, owner_column, "logical"))
    return sorted(found)


def unowned_shared_keys(tables: dict[str, Table], domain: str, rels: list[Relation]) -> dict[str, list[str]]:
    """Key-like columns that two or more tables in a domain share without a derivable owner."""
    members = _members(tables, domain)
    joined = {(r.child, r.column) for r in rels} | {(r.parent, r.parent_column) for r in rels}
    shared: dict[str, list[str]] = defaultdict(list)
    for table in members:
        for column in table.columns():
            keyish = column == "scan_id" or column.endswith("_id") or _is_identity_column(column)
            if keyish and column not in TENANT_COLUMNS and column != "id" and (table.name, column) not in joined:
                shared[column].append(table.name)
    return {c: names for c, names in sorted(shared.items()) if len(names) > 1}


def key_columns(table: Table, rels: list[Relation]) -> list[str]:
    joined = {r.column for r in rels if r.child == table.name} | {r.parent_column for r in rels if r.parent == table.name}
    wanted = set(table.primary_key) | joined | {fk[0] for fk in table.foreign_keys}
    columns = table.columns(table.primary.dialect)
    wanted |= {c for c in columns if c in TENANT_COLUMNS or c == "scan_id" or _is_identity_column(c)}
    return [c for c in columns if c in wanted] or columns[:1]


# ── rendering ──────────────────────────────────────────────────────────────────


def _code(value: str) -> str:
    return f"`{value}`"


def _codes(values: list[str]) -> str:
    return ", ".join(_code(v) for v in values) or "—"


def _domain_titles() -> dict[str, str]:
    return {key: title for key, title, _e, _p in DOMAINS}


def _attribute(table: Table, column: str) -> str:
    type_name = next((d.types[column] for d in table.defs if column in d.types), "text")
    marks = [m for m, hit in (("PK", column in table.primary_key), ("FK", column in {f[0] for f in table.foreign_keys})) if hit]
    return f"    {re.sub(r'[^a-z0-9_]', '_', type_name)} {column}{' ' + ', '.join(marks) if marks else ''}"


def _er_diagram(domain: str, tables: dict[str, Table], rels: list[Relation]) -> tuple[list[str], list[str]]:
    members = _members(tables, domain)
    names = {t.name for t in members}
    shown = [r for r in rels if r.child in names or (r.parent in names and r.kind == "fk")]
    external = sorted({n for r in shown for n in (r.parent, r.child)} - names)
    lines = ["```mermaid", "erDiagram"]
    for table in members + [tables[n] for n in external]:
        lines.append(f"  {table.name} {{")
        lines += [_attribute(table, c) for c in key_columns(table, rels)]
        lines.append("  }")
    for r in shown:
        link = "||--o{" if r.kind == "fk" else "||..o{"
        label = r.column if r.kind == "fk" else f"logical {r.column}"
        lines.append(f'  {r.parent} {link} {r.child} : "{label}"')
    lines.append("```")
    return lines, external


def _tenant_column(table: Table) -> str:
    return next((c for c in TENANT_COLUMNS if c in table.columns(table.primary.dialect)), "")


def divergences(tables: dict[str, Table]) -> list[tuple[str, list[str], list[str]]]:
    """Tables defined for Postgres and for SQLite whose column sets differ: (table, Postgres-only, SQLite-only)."""
    found = []
    for table in tables.values():
        pg = {c for d in table.defs if d.dialect == "postgres" for c in d.columns}
        lite = {c for d in table.defs if d.dialect == "sqlite" for c in d.columns}
        if pg and lite and pg != lite:
            found.append((table.name, sorted(pg - lite), sorted(lite - pg)))
    return found


def _header(title: str, intro: str, generator: str) -> list[str]:
    return [
        f"# {title}",
        "",
        f"> Generated from the code by `{generator}`. Do not edit by hand: re-run the",
        "> generator and commit the result. CI runs it with `--check` and fails on drift.",
        "",
        intro,
        "",
    ]


def _sources_lines() -> list[str]:
    lines = ["| Source | Dialect |", "|---|---|"]
    lines += [f"| {_code(path)} | {DIALECT_LABEL[dialect]} |" for path, dialect in _FIXED_DIALECT.items()]
    lines.append(
        "| `src/agent_bom/**/*.py` string literals | ClickHouse, Snowflake, SQLite or Postgres, from the module path, "
        "the enclosing class/function name, dialect-only syntax, and whether the module imports `sqlite3` |"
    )
    lines += ["", "Excluded:", ""]
    lines += [f"- {_code(module)}: {reason}" for module, reason in EXCLUDED_MODULES.items()]
    return lines


def _domain_flow(tables: dict[str, Table], rels: list[Relation]) -> list[str]:
    counts: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    for r in rels:
        src, dst = tables[r.parent].domain, tables[r.child].domain
        if src != dst:
            counts[(src, dst)][0 if r.kind == "fk" else 1] += 1
    lines = ["```mermaid", "flowchart LR"]
    for key, title, _e, _p in DOMAINS:
        lines.append(f'  {key}["{title}<br/>{len(_members(tables, key))} tables"]')
    for (src, dst), (fk, logical) in sorted(counts.items()):
        label = ", ".join(p for p in (f"{fk} FK" if fk else "", f"{logical} logical" if logical else "") if p)
        lines.append(f'  {src} -- "{label}" --> {dst}')
    lines.append("```")
    return lines


def render_index(tables: dict[str, Table], rels: list[Relation], generator: str) -> list[str]:
    titles = _domain_titles()
    fk = sum(1 for r in rels if r.kind == "fk")
    out = _header(
        "Storage ERD",
        "Every table agent-bom creates, read from the DDL in the code: the Postgres control-plane schema "
        "(bootstrap SQL and Alembic revisions), the stores' own bootstrap DDL for Postgres and SQLite, "
        "the ClickHouse analytics schema and the Snowflake schema. "
        "Back to the [data model](../DATA_MODEL.md).",
        generator,
    )
    out += [
        "## Overview",
        "",
        f"{len(tables)} tables in {len(DOMAINS)} domains. {fk} declared foreign keys; "
        f"{len(rels) - fk} logical joins derived from shared key-column names. "
        "Arrows count relations that cross domains.",
        "",
        *_domain_flow(tables, rels),
        "",
        "| Domain | Tables | Page |",
        "|---|---|---|",
    ]
    for key, title, _e, _p in DOMAINS:
        out.append(f"| {title} | {len(_members(tables, key))} | [storage-erd/{key}.md](storage-erd/{key}.md) |")
    out += [
        "",
        "## How relations are derived",
        "",
        "- **Declared** (solid line): a `REFERENCES` clause or `FOREIGN KEY` constraint in the DDL.",
        "- **Logical** (dashed line, labelled `logical`): tables in the same domain and backend family share a "
        "key column with an owning table. The owner is the target of a declared foreign key on that column name, "
        "or the one table whose primary key is that column (apart from the tenant column). "
        f"Generic names ({_codes(sorted(GENERIC_KEYS))}) join only between tables that share a name stem. "
        "Logical joins are not enforced by the database.",
        f"- Tenant columns ({_codes(list(TENANT_COLUMNS))}) scope every row to a tenant and are part of every "
        "logical join where both tables carry one; they are shown as columns, not drawn as relations.",
        "- Diagrams show key columns only: primary key, foreign keys, tenant, `scan_id`, canonical/stable ids and logical join columns.",
        "",
        "## Sources",
        "",
        *_sources_lines(),
        "",
        "## Table index",
        "",
        "| Table | Domain | Backends | Primary key | Key columns | Tenant column | Defined in |",
        "|---|---|---|---|---|---|---|",
    ]
    for table in tables.values():
        modules = [m.replace("src/agent_bom/", "").replace("deploy/supabase/", "deploy/") for m in table.modules]
        shown = ", ".join(_code(m) for m in modules[:3]) + (f" (+{len(modules) - 3})" if len(modules) > 3 else "")
        out.append(
            f"| {_code(table.name)} | [{titles[table.domain]}](storage-erd/{table.domain}.md) | "
            f"{', '.join(DIALECT_LABEL[d] for d in table.dialects)} | {_codes(table.primary_key)} | "
            f"{_codes(key_columns(table, rels))} | {_code(_tenant_column(table)) if _tenant_column(table) else '**none**'} | {shown} |"
        )
    out += _render_oddities(tables)
    return out


def _render_oddities(tables: dict[str, Table]) -> list[str]:
    out = [
        "",
        "## Schema notes",
        "",
        "### Tables without a tenant column",
        "",
        "Rows in these tables are not scoped by `tenant_id` / `team_id`. Many are global by design "
        "(vulnerability intelligence, schema metadata); the rest are worth a second look.",
        "",
        "| Table | Domain | Backends |",
        "|---|---|---|",
    ]
    titles = _domain_titles()
    out += [
        f"| {_code(t.name)} | {titles[t.domain]} | {', '.join(DIALECT_LABEL[d] for d in t.dialects)} |"
        for t in tables.values()
        if not _tenant_column(t)
    ]
    out += [
        "",
        "### Tenant column outside the primary key",
        "",
        "These tables carry a tenant column, but their primary key (per backend) does not include it, so two "
        "tenants cannot hold the same key value.",
        "",
        "| Table | Backend | Primary key | Tenant column |",
        "|---|---|---|---|",
    ]
    for t in tables.values():
        for d in sorted(t.defs, key=lambda d: (DIALECT_ORDER.index(d.dialect), d.module)):
            tenant = next((c for c in TENANT_COLUMNS if c in d.columns), "")
            row = f"| {_code(t.name)} | {DIALECT_LABEL[d.dialect]} | {_codes(d.primary_key)} | {_code(tenant) if tenant else ''} |"
            if tenant and d.primary_key and tenant not in d.primary_key and row not in out:
                out.append(row)
    out += [
        "",
        "### Postgres and SQLite column differences",
        "",
        "Tables defined for both backends whose column sets differ (columns added by `ALTER TABLE … ADD COLUMN` included).",
        "",
        "| Table | Postgres only | SQLite only |",
        "|---|---|---|",
    ]
    out += [f"| {_code(name)} | {_codes(pg)} | {_codes(lite)} |" for name, pg, lite in divergences(tables)]
    return out


def render_domain(domain: str, tables: dict[str, Table], rels: list[Relation], generator: str) -> list[str]:
    title = _domain_titles()[domain]
    members = _members(tables, domain)
    diagram, external = _er_diagram(domain, tables, rels)
    out = _header(title, "Storage tables in this domain. Back to the [storage ERD](../storage-erd.md).", generator)
    out += [f"{len(members)} tables.", ""]
    if external:
        out += [f"Tables from other domains drawn for their relations: {_codes(external)}.", ""]
    out += [*diagram, "", "## Relations", "", "| Parent | Child | Column | Kind |", "|---|---|---|---|"]
    names = {t.name for t in members}
    for r in rels:
        if r.parent in names or r.child in names:
            column = r.column if r.column == r.parent_column else f"{r.column} → {r.parent}.{r.parent_column}"
            out.append(f"| {_code(r.parent)} | {_code(r.child)} | {_code(column)} | {'declared FK' if r.kind == 'fk' else 'logical'} |")
    shared = unowned_shared_keys(tables, domain, rels)
    if shared:
        out += [
            "",
            "## Shared key columns without an owning table",
            "",
            "Same column name in several tables here, but no table owns it, so no join is drawn.",
            "",
            "| Column | Tables |",
            "|---|---|",
        ]
        out += [f"| {_code(c)} | {_codes(n)} |" for c, n in shared.items()]
    out += ["", "## Tables", "", "| Table | Backends | Columns | Partitioned |", "|---|---|---|---|"]
    for t in members:
        out.append(
            f"| {_code(t.name)} | {', '.join(DIALECT_LABEL[d] for d in t.dialects)} | {len(t.columns())} | "
            f"{'yes' if any(d.partitioned for d in t.defs) else ''} |"
        )
    return out


def render(root: Path, generator: str) -> dict[str, list[str]]:
    tables = assign_domains(extract_tables(root))
    rels = relations(tables)
    docs = {INDEX_DOC: render_index(tables, rels, generator)}
    for key, _title, _e, _p in DOMAINS:
        docs[f"{DOMAIN_DOC_DIR}/{key}.md"] = render_domain(key, tables, rels, generator)
    return docs
