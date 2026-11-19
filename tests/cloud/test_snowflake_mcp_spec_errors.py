"""Malformed MCP specs remain incomplete while independent tools survive."""

from unittest.mock import MagicMock

import pytest

from agent_bom.cloud.snowflake_ai_surfaces import _describe_mcp_server_tools
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings


@pytest.fixture(autouse=True)
def scan_state():
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def describe(rows):
    conn = MagicMock()
    cursor = conn.cursor.return_value
    cursor.description = [("property",), ("property_value",)]
    cursor.fetchall.return_value = rows
    warnings = []
    tools = _describe_mcp_server_tools(conn, "SERVER", "DB", "PUBLIC", warnings)
    cursor.close.assert_called_once()
    return tools, warnings


@pytest.mark.parametrize("spec", ["tools: [", "[]", "null", "{}", "tools: null", "tools: {}", "tools: private-marker"])
def test_malformed_spec_is_not_empty_success(spec):
    tools, warnings = describe([("spec", spec)])
    assert tools == []
    assert len(warnings) == 1
    assert "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]
    coverage = consume_coverage_warnings()
    assert len(coverage) == 1
    assert coverage[0]["reason"] == "inventory_evaluation_failed"


@pytest.mark.parametrize("bad", ["null", "42", "{}", "{name: 42}", "{name: bad, description: []}", "{name: bad, type: []}"])
def test_bad_tool_keeps_later_tools(bad):
    spec = f"tools:\n  - name: first\n  - {bad}\n  - name: next\n    type: SYSTEM_EXECUTE_SQL\n"
    tools, warnings = describe([("spec", spec)])
    assert [tool.name for tool in tools] == ["first", "next"]
    assert "HIGH-RISK" in tools[1].description
    assert len(warnings) == 1
    assert consume_coverage_warnings()


def test_invalid_spec_keeps_later_spec_row():
    tools, warnings = describe([("spec", "tools: ["), ("definition", "tools: [{name: next}]")])
    assert [tool.name for tool in tools] == ["next"]
    assert len(warnings) == 1


def test_explicit_empty_tools_is_complete():
    tools, warnings = describe([("spec", "tools: []")])
    assert (tools, warnings) == ([], [])
    assert consume_coverage_warnings() == []


@pytest.mark.parametrize("rows", [[], [("owner", "role")]])
def test_absent_spec_is_incomplete(rows):
    tools, warnings = describe(rows)
    assert tools == []
    assert len(warnings) == 1
    assert consume_coverage_warnings()


def test_missing_yaml_parser_is_incomplete(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "yaml", None)
    tools, warnings = describe([("spec", "tools: []")])
    assert tools == []
    assert len(warnings) == 1
    assert consume_coverage_warnings()
