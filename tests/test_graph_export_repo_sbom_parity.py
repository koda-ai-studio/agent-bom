"""A repository + SBOM scan exports the same nodes and edges the persisted scan graph serves."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.core.severity import Severity
from agent_bom.domain.vulnerability_model import Vulnerability

_SBOM = Path(__file__).parent / "fixtures" / "finding_matrix" / "sbom.cdx.json.fixture"
# Offline CI has no advisory database, so the lookup is pinned to known advisories.
_ADVISORIES = {
    ("jinja2", "2.10"): ("CVE-2019-10906", "CVE-2020-28493"),
    ("requests", "2.19.0"): ("CVE-2018-18074",),
    ("pyyaml", "5.3"): ("CVE-2020-14343",),
}


async def _pinned_advisories(packages, **_kwargs) -> int:
    count = 0
    for pkg in packages:
        for vuln_id in _ADVISORIES.get((pkg.name.lower(), pkg.version), ()):
            if all(existing.id != vuln_id for existing in pkg.vulnerabilities):
                pkg.vulnerabilities.append(Vulnerability(id=vuln_id, summary=vuln_id, severity=Severity.HIGH))
                count += 1
    return count


@cache
def _repo_sbom_outputs(root: str) -> tuple[dict, dict]:
    project = Path(root) / "repo"
    project.mkdir(parents=True, exist_ok=True)
    (project / "requirements.txt").write_text("jinja2==2.10\nrequests==2.19.0\npyyaml==5.3\n")
    sbom = Path(root) / "legacy.cdx.json"
    sbom.write_text(_SBOM.read_text())
    outputs = []
    with (
        mock.patch("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: None),
        mock.patch("agent_bom.scanners.scan_packages", _pinned_advisories),
    ):
        for fmt in ("json", "graph"):
            out = Path(root) / f"repo-sbom.{fmt}.json"
            result = CliRunner().invoke(
                main,
                ["scan", "-p", str(project), "--sbom", str(sbom), "--offline", "--no-auto-update-db", "--quiet"]
                + ["--format", fmt, "--output", str(out)],
                catch_exceptions=False,
            )
            assert out.exists(), result.output
            outputs.append(json.loads(out.read_text()))
    return outputs[0], outputs[1]


def _served(report: dict, tmp_path: Path, monkeypatch) -> tuple[dict[str, str], set[tuple[str, str, str]]]:
    from agent_bom.api import pipeline
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import ScanJob, ScanRequest

    store = SQLiteGraphStore(tmp_path / "repo-sbom.db")
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)
    job = ScanJob(job_id="repo-sbom-scan", tenant_id="default", created_at="2026-10-24T00:00:00Z", request=ScanRequest())
    pipeline._persist_graph_snapshot(job, {**report, "scan_id": "repo-sbom-scan"})
    graph = store.load_graph(tenant_id="default", scan_id="repo-sbom-scan")
    nodes = {node.id: node.entity_type.value for node in graph.nodes.values()}
    edges = {(edge.source, edge.target, edge.relationship.value) for edge in graph.edges}
    return nodes, edges


def _assert_fixture_shape(report: dict, served_nodes: dict[str, str], served_edges: set[tuple[str, str, str]]) -> None:
    assert {"sbom", "project"} <= {agent.get("source") for agent in report["agents"]}
    assert served_nodes.get("directory:.") == "directory"
    assert served_nodes.get("config_file:requirements.txt") == "config_file"
    assert [nid for nid, kind in served_nodes.items() if nid.startswith("source_file:sbom:") and kind == "source_file"]
    assert len([nid for nid, kind in served_nodes.items() if kind == "vulnerability"]) == 4
    manifest_rollups = {e for e in served_edges if e[0].startswith("directory:manifest:") and e[2] == "vulnerable_to"}
    assert len(manifest_rollups) == 4


def test_cli_graph_format_names_repo_and_sbom_nodes_with_persisted_graph_ids(tmp_path, tmp_path_factory, monkeypatch):
    report, cytoscape = _repo_sbom_outputs(str(tmp_path_factory.getbasetemp() / "repo-sbom-parity"))
    served_nodes, served_edges = _served(report, tmp_path, monkeypatch)
    _assert_fixture_shape(report, served_nodes, served_edges)

    nodes = {e["data"]["id"]: e["data"].get("entity_type") for e in cytoscape["elements"] if "source" not in e["data"]}
    edges = {(e["data"]["source"], e["data"]["target"]) for e in cytoscape["elements"] if "source" in e["data"]}
    assert {nid: kind for nid, kind in nodes.items() if served_nodes.get(nid) != kind} == {}
    assert {"directory:.", "config_file:requirements.txt"} <= set(nodes)
    assert [nid for nid in nodes if nid.startswith("source_file:sbom:")]
    assert len([nid for nid, kind in nodes.items() if kind == "vulnerability"]) == 4
    assert edges - {(source, target) for source, target, _ in served_edges} == set()


def _canonical_edge(edge: dict) -> tuple[str, str, str]:
    """The export keeps the legacy ``affects`` label on the package -> vulnerability edge."""
    relationship = "vulnerable_to" if edge["relationship"] == "affects" and edge["target"].startswith("vuln:") else edge["relationship"]
    return edge["source"], edge["target"], relationship


def test_scan_graph_export_equals_persisted_graph_for_repo_and_sbom(tmp_path, tmp_path_factory, monkeypatch):
    from agent_bom.api.scan_graph_view import _graph_export_response
    from agent_bom.output.graph_export import build_graph_from_scan_data, to_json

    report, _ = _repo_sbom_outputs(str(tmp_path_factory.getbasetemp() / "repo-sbom-parity"))
    served_nodes, served_edges = _served(report, tmp_path, monkeypatch)
    _assert_fixture_shape(report, served_nodes, served_edges)

    api = _graph_export_response(report, format="json", mermaid_limit=80, scan_id="repo-sbom-scan", tenant_id="default")
    assert isinstance(api, dict)
    for exported in (api, to_json(build_graph_from_scan_data(report))):
        assert {node["id"]: node["entity_type"] for node in exported["nodes"]} == served_nodes
        assert {_canonical_edge(edge) for edge in exported["edges"]} == served_edges
        legacy = {(e["source"], e["target"]) for e in exported["edges"] if e["relationship"] == "affects"}
        assert legacy and all(source.startswith("pkg:") and target.startswith("vuln:") for source, target in legacy)
        assert exported["stats"] == {"node_count": len(served_nodes), "edge_count": len(served_edges)}
