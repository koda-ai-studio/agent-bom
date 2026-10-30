"""Imported row scope and observation times survive graph projection/storage."""

from copy import deepcopy

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.builder import build_unified_graph_from_report
from tests.test_lake_evidence_ingest import build, fixture


@pytest.mark.parametrize("asset_type", ["cloud_resource", "data_store", "identity", "container", "package", "agent", "mcp_server"])
def test_lake_graph_asset_retains_region_and_environment(tmp_path, asset_type):
    rows, mapping = fixture()
    mapping["asset_type"] = asset_type
    rows[0]["environment"] = "prod"
    report = build(rows, mapping)
    graph = build_unified_graph_from_report(report, scan_id="lake-scope", tenant_id="lake")
    store = SQLiteGraphStore(tmp_path / "lake.db")
    store.save_graph(graph)
    restored = store.load_graph(scan_id="lake-scope", tenant_id="lake")
    for snapshot in (graph, restored):
        asset = next(node for node in snapshot.nodes.values() if node.attributes.get("identifier") == "bucket-one")
        assert asset.attributes["region"] == "us-east-1"
        assert asset.attributes["environment"] == "prod"
        assert asset.attributes["account_id"] == "aws:sample-account-one"
    assert not store.load_graph(scan_id="lake-scope", tenant_id="another-tenant").nodes


def test_lake_graph_rows_keep_their_own_observation_times(tmp_path):
    rows, mapping = fixture()
    older = deepcopy(rows[0])
    older["finding_info"]["uid"] = "older-finding"
    older["resources"][0]["uid"] = "older-bucket"
    older["observed_at"] = "2026-10-01T00:00:00Z"
    report = build([older, *rows], mapping)
    graph = build_unified_graph_from_report(report, scan_id="lake-time", tenant_id="lake")
    store = SQLiteGraphStore(tmp_path / "lake-time.db")
    store.save_graph(graph)
    graph = store.load_graph(scan_id="lake-time", tenant_id="lake")
    for row in report["findings"]:
        asset = graph.nodes[row["node_id"]]
        edge = next(edge for edge in graph.edges if edge.source == asset.id)
        finding = graph.nodes[edge.target]
        expected = row["first_seen"]
        assert (asset.first_seen, asset.last_seen) == (expected, expected)
        assert (finding.first_seen, finding.last_seen) == (expected, expected)
        assert (edge.first_seen, edge.last_seen) == (expected, expected)
