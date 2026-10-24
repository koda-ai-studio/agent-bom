"""Every graph export names nodes with the canonical id and entity type the graph API serves."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType
from agent_bom.output.graph_export import build_graph_from_scan_data, to_json

_ENTITY_TYPES = {entity.value for entity in EntityType}


@cache
def _demo_outputs(root: str) -> tuple[dict, dict]:
    outputs = []
    Path(root).mkdir(parents=True, exist_ok=True)
    with mock.patch("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: None):
        for fmt in ("json", "graph"):
            out = Path(root) / f"demo.{fmt}.json"
            result = CliRunner().invoke(
                main,
                ["scan", "--demo", "--offline", "--no-auto-update-db", "--quiet", "--format", fmt, "--output", str(out)],
                catch_exceptions=False,
            )
            assert out.exists(), result.output
            outputs.append(json.loads(out.read_text()))
    return outputs[0], outputs[1]


def _canonical(report: dict) -> dict[str, str]:
    graph = build_unified_graph_from_report(report)
    return {node_id: node.entity_type.value for node_id, node in graph.nodes.items()}


def test_cli_graph_format_uses_canonical_ids_and_entity_types(tmp_path_factory):
    report, cytoscape = _demo_outputs(str(tmp_path_factory.getbasetemp() / "graph-parity"))
    canonical = _canonical(report)
    nodes = [element["data"] for element in cytoscape["elements"] if "source" not in element["data"]]
    assert nodes
    mismatched = [(node["id"], node.get("entity_type")) for node in nodes if canonical.get(node["id"]) != node.get("entity_type")]
    assert mismatched == []
    # The display kind stays available to the HTML renderer.
    assert {"server_cred", "pkg_vuln", "cve", "finding"} <= {node["type"] for node in nodes}
    ids = {node["id"] for node in nodes}
    for element in cytoscape["elements"]:
        if "source" in element["data"]:
            assert {element["data"]["source"], element["data"]["target"]} <= ids


def test_graph_export_json_uses_canonical_ids_and_entity_types(tmp_path_factory):
    report, _ = _demo_outputs(str(tmp_path_factory.getbasetemp() / "graph-parity"))
    canonical = _canonical(report)
    exported = to_json(build_graph_from_scan_data(report))["nodes"]
    assert {node["entity_type"] for node in exported} <= _ENTITY_TYPES
    mismatched = [(node["id"], node["entity_type"]) for node in exported if canonical.get(node["id"]) != node["entity_type"]]
    assert mismatched == []
    core = {"agent", "server", "tool", "credential", "package", "vulnerability"}
    assert {nid for nid, kind in canonical.items() if kind in core} <= {node["id"] for node in exported}
    assert {"pkg_vuln", "cve", "server_cred"} <= {node["kind"] for node in exported}


def test_scan_graph_export_joins_the_persisted_scan_graph(tmp_path, tmp_path_factory, monkeypatch):
    from agent_bom.api import pipeline
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import ScanJob, ScanRequest
    from agent_bom.api.scan_graph_view import _graph_export_response

    report, _ = _demo_outputs(str(tmp_path_factory.getbasetemp() / "graph-parity"))
    store = SQLiteGraphStore(tmp_path / "parity.db")
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)
    job = ScanJob(job_id="parity-scan", tenant_id="default", created_at="2026-10-23T00:00:00Z", request=ScanRequest())
    pipeline._persist_graph_snapshot(job, {**report, "scan_id": "parity-scan"})

    served = {node.id: node.entity_type.value for node in store.load_graph(tenant_id="default", scan_id="parity-scan").nodes.values()}
    exported = _graph_export_response(report, format="json", mermaid_limit=80, scan_id="parity-scan", tenant_id="default")
    assert isinstance(exported, dict)
    by_id = {node["id"]: node["entity_type"] for node in exported["nodes"]}
    assert served and by_id
    assert {nid: kind for nid, kind in by_id.items() if served.get(nid) != kind} == {}


_INVENTORY_KINDS = {"agent", "server", "tool", "credential", "provider"}


@cache
def _showcase(root: str) -> tuple[dict, dict[str, str]]:
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.demo_estate.bootstrap import _run_demo_scan_report
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_SCAN_ID, SHOWCASE_TENANT, seed_showcase_graph_if_empty

    Path(root).mkdir(parents=True, exist_ok=True)
    report = _run_demo_scan_report(tenant_id=SHOWCASE_TENANT)
    store = SQLiteGraphStore(Path(root) / "showcase.db")
    assert seed_showcase_graph_if_empty(store, tenant_id=SHOWCASE_TENANT, force=True, scan_report=lambda: report)
    snapshot = store.load_graph(tenant_id=SHOWCASE_TENANT, scan_id=SHOWCASE_SCAN_ID)
    return report, {node_id: node.entity_type.value for node_id, node in snapshot.nodes.items()}


def test_showcase_job_export_joins_the_showcase_snapshot(tmp_path_factory):
    report, snapshot = _showcase(str(tmp_path_factory.getbasetemp() / "showcase-parity"))
    exported = {node["id"]: node["entity_type"] for node in to_json(build_graph_from_scan_data(report))["nodes"]}
    joined_kinds = _INVENTORY_KINDS | {"package", "vulnerability"}
    exported_inventory = {nid: kind for nid, kind in exported.items() if kind in joined_kinds}
    assert {kind for kind in exported_inventory.values()} >= _INVENTORY_KINDS
    assert {nid: kind for nid, kind in exported_inventory.items() if snapshot.get(nid) != kind} == {}


def test_showcase_inventory_nodes_are_the_ids_the_export_names(tmp_path_factory):
    from agent_bom.demo_estate.showcase_graph import build_showcase_graph

    report, _ = _showcase(str(tmp_path_factory.getbasetemp() / "showcase-parity"))
    exported = {node["id"] for node in to_json(build_graph_from_scan_data(report))["nodes"]}
    showcase, _, _ = build_showcase_graph(profile="current")
    drawn = {nid: node.entity_type.value for nid, node in showcase.nodes.items() if node.entity_type.value in _INVENTORY_KINDS}
    counts: dict[str, int] = {}
    for kind in drawn.values():
        counts[kind] = counts.get(kind, 0) + 1
    assert counts == {"agent": 5, "server": 10, "tool": 26, "credential": 15, "provider": 1}
    assert sorted(nid for nid in drawn if nid not in exported) == []


def test_cli_demo_export_names_only_showcase_snapshot_ids(tmp_path_factory):
    _, snapshot = _showcase(str(tmp_path_factory.getbasetemp() / "showcase-parity"))
    report, _ = _demo_outputs(str(tmp_path_factory.getbasetemp() / "graph-parity"))
    exported = {node["id"]: node["entity_type"] for node in to_json(build_graph_from_scan_data(report))["nodes"]}
    inventory = {nid: kind for nid, kind in exported.items() if kind in _INVENTORY_KINDS | {"package", "vulnerability"}}
    assert {nid: kind for nid, kind in inventory.items() if snapshot.get(nid) != kind} == {}


def test_cli_demo_leaves_the_shared_demo_inventory_untouched(tmp_path_factory):
    from agent_bom.demo import DEMO_INVENTORY

    _demo_outputs(str(tmp_path_factory.getbasetemp() / "graph-parity"))
    assert [agent.get("config_path") for agent in DEMO_INVENTORY["agents"]] == [None] * len(DEMO_INVENTORY["agents"])


_ESTATE_KINDS = {"cloud_resource", "data_store"}
# The conservative package->tool mapping records no evidence tier for the demo's
# collector; strict mode would drop the whole unified graft these tests read.
_KNOWN_CONTRACT_GAPS = {"missing_evidence_tier: exploitable_via vulnerability->tool"}
_estate_parity = pytest.mark.graph_contract("warn")


def _showcase_export(report: dict) -> list[dict]:
    return to_json(build_graph_from_scan_data(report))["nodes"]


@_estate_parity
def test_showcase_report_graph_breaks_no_relationship_contract_beyond_known_gaps(tmp_path_factory):
    report, _ = _showcase(str(tmp_path_factory.getbasetemp() / "showcase-parity"))
    from agent_bom.graph.relationship_contract import audit_graph_contract

    audit = audit_graph_contract(build_unified_graph_from_report(report), record=False)
    assert set(audit["pairs"]) | set(audit["rejected_pairs"]) <= _KNOWN_CONTRACT_GAPS


@_estate_parity
def test_showcase_job_export_names_cloud_resources_and_data_stores_as_the_snapshot(tmp_path_factory):
    report, snapshot = _showcase(str(tmp_path_factory.getbasetemp() / "showcase-parity"))
    nodes = _showcase_export(report)
    exported = {node["id"]: node["entity_type"] for node in nodes if node["entity_type"] in _ESTATE_KINDS}
    # The CNAPP overlay gives a keyword-matched cloud resource a data-store companion;
    # the showcase projects its estate after that overlay, so only the backing resource joins.
    companions = {nid: nid.removeprefix("data_store:") for nid in exported if nid.startswith("data_store:")}
    companions = {nid: backing for nid, backing in companions.items() if backing in exported}
    assert len(exported) > 700
    assert {nid: kind for nid, kind in exported.items() if nid not in companions and snapshot.get(nid) != kind} == {}
    assert {backing for backing in companions.values() if snapshot.get(backing) != "cloud_resource"} == set()
    assert not [nid for nid in exported if nid.startswith(("cloud_resource:aws:arn:", "data_store:cloud_resource:"))]


@_estate_parity
def test_showcase_snapshot_cloud_assets_the_report_names_reach_the_export(tmp_path_factory):
    report, snapshot = _showcase(str(tmp_path_factory.getbasetemp() / "showcase-parity"))
    exported = {node["id"]: node["entity_type"] for node in _showcase_export(report)}
    named = {row["node_id"] for row in report["findings"] if snapshot.get(row.get("node_id") or "") in _ESTATE_KINDS}
    for section in ("cis_benchmark", "azure_cis_benchmark", "gcp_cis_benchmark", "snowflake_cis_benchmark"):
        for check in (report.get(section) or {}).get("checks", []):
            if str(check.get("status", "")).upper() == "FAIL":
                named |= {rid for rid in check.get("resource_ids", []) if snapshot.get(rid) in _ESTATE_KINDS}
    drawn = {nid for nid in named if nid in exported}
    assert len(named) > 700
    assert {nid: (snapshot[nid], exported[nid]) for nid in drawn if exported[nid] != snapshot[nid]} == {}
    # One finding node anchors one asset in a report-built graph, so an IaC rule shared
    # by many assets draws only its first; no named asset reaches the export under another id.
    assert len(drawn) >= 0.98 * len(named)
    assert not [nid for nid in exported if nid.startswith("cloud_resource:") and nid.split(":", 2)[-1] in named]
    # The multi-source compute lane joins on its merged strong-key id, not the posture row's ARN.
    lane = {nid for nid in named if nid.startswith("cloud_resource:aws:aws_instance:")}
    assert len(lane) == 12


_STATIC_INVENTORY_KINDS = {"agent", "server", "provider", "source_file", "directory", "package", "vulnerability"}


@cache
def _sbom_and_repository_report(root: str) -> dict:
    project = Path(root) / "project"
    project.mkdir(parents=True, exist_ok=True)
    (project / "requirements.txt").write_text("requests==2.31.0\n")
    sbom = Path(__file__).parent / "fixtures" / "test-sbom.cdx.json"
    out = Path(root) / "sbom-repo.json"
    with mock.patch("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: None):
        result = CliRunner().invoke(
            main,
            ["scan", "-p", str(project), "--sbom", str(sbom), "--offline", "--no-auto-update-db", "--quiet"]
            + ["--format", "json", "--output", str(out)],
            catch_exceptions=False,
        )
    assert out.exists(), result.output
    return json.loads(out.read_text())


def test_sbom_and_repository_inventory_export_with_the_graph_ids(tmp_path_factory):
    report = _sbom_and_repository_report(str(tmp_path_factory.getbasetemp() / "sbom-repo-parity"))
    sources = {agent.get("source") for agent in report["agents"]}
    assert {"sbom", "project"} <= sources
    canonical = _canonical(report)
    exported = {node["id"]: node["entity_type"] for node in to_json(build_graph_from_scan_data(report))["nodes"]}
    inventory = {nid: kind for nid, kind in exported.items() if kind in _STATIC_INVENTORY_KINDS}
    assert {nid: kind for nid, kind in inventory.items() if canonical.get(nid) != kind} == {}
    static_prefixes = ("source_file:sbom:", "directory:repository:", "directory:manifest:")
    static = {nid for nid in canonical if nid.startswith(static_prefixes)}
    assert len(static) == 3
    assert static <= set(exported)
    assert not [nid for nid in exported if nid.startswith(("provider:sbom", "provider:project"))]
