"""Quiet explicit scans and findings without agent context have honest displays."""

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from rich.table import Table

from agent_bom.cli.agents._discovery_sources import _discover_from, print_discovery_header
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output.console_render import print_blast_radius


def test_quiet_explicit_project_does_not_announce_discovery():
    console = MagicMock()
    run = SimpleNamespace(
        quiet=True,
        verbose=False,
        con=console,
        discover=Mock(return_value=[]),
        dynamic_discovery=False,
        dynamic_max_depth=1,
        include_processes=False,
        include_containers=False,
        k8s_mcp=False,
        k8s_namespace="default",
        k8s_all_namespaces=False,
        k8s_mcp_context=None,
    )
    print_discovery_header(run)
    _discover_from(run, "/test/project")
    run.discover.assert_called_once()
    console.print.assert_not_called()
    console.status.assert_not_called()


@pytest.mark.parametrize("agents", [[], ["test-agent"]])
def test_blast_column_requires_agent_context(monkeypatch, agents):
    console = MagicMock()
    monkeypatch.setattr("agent_bom.output.console_render._console", lambda: console)
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="test-package", asset_type="package", identifier="pkg:pypi/test-package@1"),
        severity="critical",
        title="Test vulnerability",
        cve_id="CVE-2024-0001",
        is_actionable=True,
        risk_score=9.0,
        affected_agents=agents,
    )
    print_blast_radius(AIBOMReport(findings=[finding]))
    table = next(call.args[0] for call in console.print.call_args_list if call.args and isinstance(call.args[0], Table))
    assert ("Blast" in [column.header for column in table.columns]) is bool(agents)
    assert "Vulnerability" in [column.header for column in table.columns]
