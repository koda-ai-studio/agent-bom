"""Bounded graph export and refusal to render charts with symlink inputs."""

from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from agent_bom.iac import helm_templates
from agent_bom.output.graph_export import DepGraph, to_cypher


def test_cypher_resolves_relationship_labels_in_bounded_node_passes(monkeypatch):
    graph = DepGraph()
    for index in range(200):
        graph.add_node(f"p{index}", f"Package {index}", "pkg")
        if index:
            graph.add_edge(f"p{index - 1}", f"p{index}", "depends_on")
    accesses = 0
    getter = DepGraph.nodes.fget

    def counted(self):
        nonlocal accesses
        accesses += 1
        return getter(self)

    monkeypatch.setattr(DepGraph, "nodes", property(counted))
    output = to_cypher(graph)
    assert output.count("MERGE (a)-[:DEPENDS_ON]->(b)") == 199
    assert accesses <= 4, f"node list materialized {accesses} times for 199 edges"


@pytest.mark.parametrize("name", ["values.yaml", "templates/linked.yaml", "charts/linked", "broken"])
def test_helm_refuses_every_chart_symlink_before_subprocess(tmp_path, monkeypatch, name):
    root = tmp_path / "chart"
    root.mkdir()
    (root / "Chart.yaml").write_text("apiVersion: v2\nname: sample\nversion: 1.0.0\n")
    target = tmp_path / "outside"
    target.write_text("private input")
    link = root / name
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(tmp_path / "missing" if name == "broken" else target)
    run = Mock(return_value=Mock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(helm_templates.shutil, "which", lambda _: "/usr/bin/helm")
    monkeypatch.setattr(helm_templates.subprocess, "run", run)
    output, reason = helm_templates.render_chart(root)
    assert output is None and "symlink" in reason
    run.assert_not_called()


def test_helm_textual_fallback_never_reads_link_target(tmp_path, monkeypatch):
    root = tmp_path / "chart"
    (root / "templates").mkdir(parents=True)
    (root / "Chart.yaml").write_text("apiVersion: v2\n")
    target = tmp_path / "private.yaml"
    target.write_text("privileged: true\n")
    (root / "templates/linked.yaml").symlink_to(target)
    monkeypatch.setattr(helm_templates.shutil, "which", lambda _: None)
    result = helm_templates.scan_chart_templates(root, tmp_path)
    assert not result.findings and "symlink" in result.reason


def test_ci_image_gate_scans_saved_artifact_with_existing_policy():
    root = Path(__file__).resolve().parents[1]
    steps = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())["jobs"]["docker"]["steps"]
    command = next(s["run"] for s in steps if s.get("name") == "Image vulnerability scan (agent-bom — dogfood)")
    assert "docker save agent-bom:test" in command
    assert "agent-bom image --tar /tmp/agent-bom-test.tar" in command
    assert "--fail-on-severity medium" in command and "--exclude-unfixable" in command
    assert "--ignore .image-scan-ignore" in command
    assert "|| true" not in command and "--offline" not in command
