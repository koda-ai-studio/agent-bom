"""Source declarations must retain case and tuple boundaries through projection."""

import pytest

from agent_bom.graph.ast_tool_projection import _project_ast_entrypoints, _project_ast_tools
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType


@pytest.mark.parametrize("entries", [False, True])
def test_case_distinct_source_declarations_do_not_collapse(entries):
    graph = UnifiedGraph(scan_id="source-identity")
    rows = [dict(file=path, name=name, handler=name) for path, name in [("src/Tools.py", "Read"), ("src/tools.py", "read")]]
    project = _project_ast_entrypoints if entries else _project_ast_tools
    project(graph, rows)
    kind = EntityType.CODE_MODULE if entries else EntityType.TOOL
    nodes = [node for node in graph.nodes.values() if node.entity_type == kind]
    assert len(nodes) == 2
    assert {(node.label, node.attributes["source_file"]) for node in nodes} == {("Read", "src/Tools.py"), ("read", "src/tools.py")}
    assert len({node.canonical_id for node in nodes}) == 2
    assert len(graph.edges) == 2
    project(graph, rows)
    assert len([node for node in graph.nodes.values() if node.entity_type == kind]) == 2


def test_source_identity_keeps_component_boundaries():
    graph = UnifiedGraph()
    _project_ast_tools(graph, [dict(file="a:b", name="c"), dict(file="a", name="b:c")])
    assert len([n for n in graph.nodes.values() if n.entity_type == EntityType.TOOL]) == 2


def test_legacy_aliases_resolve_only_when_unambiguous():
    from agent_bom.graph.node_aliases import NodeAliasCollector

    graph = UnifiedGraph()
    _project_ast_tools(graph, [dict(file="src/Tools.py", name="Read")])
    collector = NodeAliasCollector()
    list(collector.wrap(graph.nodes.values()))
    assert len(collector.records(tenant="a", scan="s", now="2026-11-25")) == 1
    _project_ast_tools(graph, [dict(file="src/tools.py", name="read")])
    collector = NodeAliasCollector()
    list(collector.wrap(graph.nodes.values()))
    assert collector.records(tenant="a", scan="s", now="2026-11-25") == []
