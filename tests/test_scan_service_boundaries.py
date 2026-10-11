"""Finding helpers remain usable below HTTP route composition."""

import ast
from pathlib import Path

import pytest


@pytest.mark.parametrize("module", ["finding_facets", "finding_grouping", "finding_view_filters", "finding_scope_filters"])
def test_finding_helpers_do_not_depend_on_scan_router(module):
    path = Path(__file__).resolve().parents[1] / "src/agent_bom/api" / f"{module}.py"
    assert path.exists(), "finding semantics must live below HTTP route composition"
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module != "agent_bom.api.routes.scan"
        elif isinstance(node, ast.Import):
            assert all(alias.name != "agent_bom.api.routes.scan" for alias in node.names)


def test_demo_graph_uses_graph_services_without_http_composition():
    path = Path(__file__).resolve().parents[1] / "src/agent_bom/demo_estate/showcase_graph.py"
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("agent_bom.api.routes")
