"""Inline reviewer suppressions are visible and reasoned, never silent drops."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from agent_bom.ast_analyzer import analyze_project
from scripts.code_scan_json_to_sarif import convert


def _analyze(tmp_path: Path, source: str):
    (tmp_path / "mod.py").write_text(textwrap.dedent(source), encoding="utf-8")
    return analyze_project(tmp_path)


def test_reasoned_sql_suppression_is_recorded_with_its_reason(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        """
        def count(conn, table):
            return conn.execute(f"SELECT COUNT(*) FROM {table}")  # nosec B608 - callers pass static table names
        """,
    )
    assert [f for f in result.flow_findings if f.category == "sql_string_construction"] == []
    [suppressed] = result.suppressed_flow_findings
    assert suppressed.category == "sql_string_construction"
    assert suppressed.line_number == 3
    assert suppressed.suppression == "nosec B608 - callers pass static table names"


def test_suppression_on_a_tracked_assignment_is_recorded(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        """
        def ecosystems(conn, placeholders, names):
            query = f"SELECT 1 FROM affected WHERE ecosystem IN ({placeholders})"  # nosec B608 - markers only
            return conn.execute(query, names).fetchall()
        """,
    )
    assert result.flow_findings == []
    [suppressed] = result.suppressed_flow_findings
    assert suppressed.suppression == "nosec B608 - markers only"


def test_bare_marker_is_recorded_as_unreasoned(tmp_path: Path) -> None:
    result = _analyze(tmp_path, 'def f(conn, uid):\n    return conn.execute(f"SELECT * FROM u WHERE id = {uid}")  # nosec\n')
    [suppressed] = result.suppressed_flow_findings
    assert suppressed.suppression == "nosec (no reason given)"


@pytest.mark.parametrize(
    ("category", "source"),
    [
        (
            "ssrf_url_construction",
            'import httpx\n\ndef f(host):\n    return httpx.get(f"{host}/x")  # nosec B310 - operator-configured endpoint\n',
        ),
        (
            "unsafe_deserialization",
            "import pickle\n\ndef f(blob):\n    return pickle.loads(blob)  # nosec B301 - signed local cache\n",
        ),
        (
            "command_string_construction",
            'import subprocess\n\ndef f(d):\n    return subprocess.run("ls " + d, shell=True)  # noqa: S602 - fixed directory set\n',
        ),
    ],
)
def test_matching_marker_suppresses_each_sink_class(tmp_path: Path, category: str, source: str) -> None:
    result = _analyze(tmp_path, source)
    assert [f for f in result.flow_findings if f.category == category] == []
    assert [f.category for f in result.suppressed_flow_findings] == [category]


@pytest.mark.parametrize(
    "source",
    [
        'import httpx\n\ndef f(host):\n    return httpx.get(f"{host}/x")  # nosec B608 - wrong rule\n',
        "import pickle\n\ndef f(blob):\n    return pickle.loads(blob)  # nosec B310\n",
        'def f(conn, uid):\n    return conn.execute(f"SELECT {uid}")  # nosec B101\n',
    ],
)
def test_marker_for_another_rule_does_not_suppress(tmp_path: Path, source: str) -> None:
    result = _analyze(tmp_path, source)
    assert len(result.flow_findings) == 1
    assert result.suppressed_flow_findings == []


def test_suppressed_findings_are_serialized_and_counted_separately(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        """
        def f(conn, table, uid):
            conn.execute(f"SELECT 1 FROM {table}")  # nosec B608 - static
            return conn.execute(f"SELECT * FROM u WHERE id = {uid}")
        """,
    )
    payload = result.to_dict()
    assert payload["stats"]["total_flow_findings"] == 1
    assert payload["stats"]["total_suppressed_flow_findings"] == 1
    [row] = payload["suppressed_flow_findings"]
    assert row["line"] == 3
    assert row["suppression"] == "nosec B608 - static"


def test_sarif_publishes_only_active_findings_and_counts_suppressed(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        """
        def f(conn, table, uid):
            conn.execute(f"SELECT 1 FROM {table}")  # nosec B608 - static
            return conn.execute(f"SELECT * FROM u WHERE id = {uid}")
        """,
    )
    sarif = convert(json.loads(json.dumps(result.to_dict())))
    run = sarif["runs"][0]
    assert [r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in run["results"]] == [4]
    assert run["properties"]["suppressedFlowFindings"] == 1
