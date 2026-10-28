"""A source-only project folds its framework constructs without a package manifest.

The ``project:<dir>`` host used to exist only when a manifest was found, so the
``langgraph_supervisor`` fixture scanned as-is (no ``requirements.txt``) drew
no ``contains`` edge and left every top-level construct a standalone agent.
The ``ai-inventory`` agent now carries the project root, so both layouts read
the same.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType

_FIXTURE = Path(__file__).parent / "fixtures" / "agent_frameworks" / "langgraph_supervisor"
_LAYOUTS = ("source-only", "with-manifest")


def _scan(root: Path, out_dir: Path, fmt: str) -> dict:
    out = out_dir / f"report.{fmt}.json"
    args = ["scan", "-p", str(root), "--ai-inventory", str(root), "--offline", "-f", fmt, "-o", str(out)]
    result = CliRunner().invoke(main, args)
    assert out.exists(), result.output
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def layouts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[dict, dict]]:
    scanned = {}
    for layout in _LAYOUTS:
        root = tmp_path_factory.mktemp(layout) / "proj"
        shutil.copytree(_FIXTURE, root)
        if layout == "with-manifest":
            (root / "requirements.txt").write_text("langgraph==0.2.0\n", encoding="utf-8")
        out_dir = tmp_path_factory.mktemp(f"{layout}-out")
        scanned[layout] = (_scan(root, out_dir, "json"), _scan(root, out_dir, "graph"))
    return scanned


def _host(report: dict) -> tuple[set[str], list[str], set[str]]:
    graph = build_unified_graph_from_report(report)
    owners = {a["name"] for a in report["agents"] if (a.get("metadata") or {}).get("project_root")}
    hosts = [n for n in graph.nodes_by_type(EntityType.AGENT) if n.label in owners]
    assert len(hosts) == 1, [n.label for n in graph.nodes_by_type(EntityType.AGENT)]
    host = hosts[0]
    contained = {graph.nodes[e.target].label for e in graph.adjacency.get(host.id, []) if e.relationship == RelationshipType.CONTAINS}
    agents = {n.label for n in graph.nodes_by_type(EntityType.AGENT)} - {host.label}
    return contained, [a["name"] for a in host.attributes.get("code_agents") or []], agents


@pytest.mark.parametrize("layout", _LAYOUTS)
def test_source_only_project_has_one_project_root_host(layouts: dict[str, tuple[dict, dict]], layout: str) -> None:
    report, _ = layouts[layout]
    hosts = [a for a in report["agents"] if (a.get("metadata") or {}).get("project_root")]
    assert [a["name"] for a in hosts] == ["project:proj"] if layout == "with-manifest" else len(hosts) == 1


def test_contains_edges_and_folding_match_the_manifest_layout(layouts: dict[str, tuple[dict, dict]]) -> None:
    source_only = _host(layouts["source-only"][0])
    with_manifest = _host(layouts["with-manifest"][0])
    assert source_only == with_manifest
    assert source_only[0] == {"builder"}  # research_builder nests under its research node


def test_graph_output_draws_the_contains_edge_without_a_manifest(layouts: dict[str, tuple[dict, dict]]) -> None:
    def shape(elements: dict) -> tuple[set[str], set[tuple[str, str]]]:
        data = [el["data"] for el in elements["elements"]]
        labels = {d["label"] for d in data if d.get("agentType") == "framework-agent"}
        by_id = {d["id"]: d.get("label", d["id"]) for d in data if "id" in d}
        contains = {(by_id.get(d["source"], ""), by_id[d["target"]]) for d in data if d.get("type") == "contains"}
        return labels, {(src.startswith("project:") or src == "ai-inventory", dst) for src, dst in contains if dst in labels}

    assert shape(layouts["source-only"][1]) == shape(layouts["with-manifest"][1])
    assert shape(layouts["source-only"][1])[1] == {(True, "builder")}
