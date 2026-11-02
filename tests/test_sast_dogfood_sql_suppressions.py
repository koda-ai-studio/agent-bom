"""The dogfood scan's reviewed SQL sites stay suppressed with their recorded reasons.

Each site interpolates only literal clauses, placeholder groups, validated
identifiers or dialect-escaped literals. The analyzer cannot follow that across
helper calls, so a reviewer marker carries the reason, and the finding must be
recorded in ``suppressed_flow_findings`` rather than published or dropped.
"""

from __future__ import annotations

import shutil
from collections import Counter
from pathlib import Path

import agent_bom
from agent_bom.ast_analyzer import analyze_project

_SQL = "sql_string_construction"

_REVIEWED_SITES: dict[str, list[str]] = {
    "api/cost_store.py": [
        "_cost_scope: literal columns, ? placeholders",
        "_cost_scope: literal columns and ? placeholders only",
    ],
    "api/postgres_cost.py": [
        "_cost_scope: literal columns, %s placeholders only",
        "scope from _cost_scope: literal column names joined with %s placeholders; values bound",
    ],
    "api/graph_store.py": ["inventory_cte is static SQL with ? groups"],
    "api/postgres_graph.py": [
        "severity_floor_sql: literal column names with %s placeholders; values bound",
        "literal clauses and %s-placeholder helper fragments only",
    ],
    "api/postgres_graph_inventory.py": ["cte is _inventory_cte(): static SQL with %s groups"],
    "api/sqlite_rekey.py": ["callers pass _CREATE_*_SQL constants; scratch is validated"],
    "api/storage/compliance_restore.py": ["ledger_upsert: fixed columns and ? placeholders"],
    "api/storage/registry_import.py": ["tables passed read_source's adapter allowlist; other names are module constants"],
    "api/store.py": ["_sqlite_job_summary_filter: literal clauses with ? only"],
    "cloud/clickhouse.py": [
        "table validated; json.dumps rows are data, not SQL",
        "executor; store callers escape values via _escape; adds only a literal FORMAT JSON",
    ],
    "export/databricks_statement.py": ["repeats only the matched (?, ...) group"],
    "export/destinations.py": [
        "validated table; tenant/run/attempt escaped by _clickhouse_literal",
        "OS temp-file path; stage ref: quoted validated table + hex ids",
        "_sf_ident-quoted validated table; stage ref of hex ids",
        "stage ref: _sf_ident-quoted validated table + hex ids",
        "stage ref: _sf_ident-quoted validated table + hex ids",
    ],
}


def _scan_reviewed_modules(tmp_path: Path):
    package_root = Path(agent_bom.__file__).resolve().parent
    for relative in _REVIEWED_SITES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(package_root / relative, target)
    return analyze_project(tmp_path)


def _relative(file_path: str, root: Path) -> str:
    candidate = Path(file_path)
    if candidate.is_absolute():
        candidate = candidate.resolve().relative_to(root.resolve())
    return candidate.as_posix()


def test_reviewed_dogfood_sql_sites_are_suppressed_with_their_reasons(tmp_path: Path) -> None:
    result = _scan_reviewed_modules(tmp_path)

    active = [(_relative(f.file_path, tmp_path), f.line_number) for f in result.flow_findings if f.category == _SQL]
    assert active == []

    recorded = Counter((_relative(f.file_path, tmp_path), f.suppression) for f in result.suppressed_flow_findings if f.category == _SQL)
    expected = Counter((relative, f"nosec B608 - {reason}") for relative, reasons in _REVIEWED_SITES.items() for reason in reasons)
    missing = expected - recorded
    assert not missing, f"reviewed sites not recorded with their reason: {sorted(missing.elements())}"
