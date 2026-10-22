"""Native Okta scope survives discovery, JSON, persistence and correlation."""

import json

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.nhi_overlay import serialize_discovery_result
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.identity.okta_nhi import discover_okta_non_human_identities
from tests.test_nhi_okta_discovery import _api_token, _FakeOktaClient, _service_app


def _snapshot(scan_id, org, *, label="service", token=False):
    client = _FakeOktaClient(
        apps=[] if token else [_service_app("native-id", label)],
        tokens=[_api_token("native-id", label)] if token else [],
    )
    result = discover_okta_non_human_identities(client=client, org_url=org)
    report = json.loads(json.dumps({"identity_discovery": serialize_discovery_result(result)}))
    return build_unified_graph_from_report(report, scan_id=scan_id, tenant_id="tenant-one")


def _merge(*graphs):
    return merge_graph_snapshots(
        correlation_id="correlated",
        tenant_id="tenant-one",
        snapshots=[CorrelationSnapshot.from_graph(graph) for graph in graphs],
    ).graph


@pytest.mark.parametrize("token", [False, True])
def test_same_scoped_native_identity_correlates_after_json_and_sqlite_restart(tmp_path, token):
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph

    graphs = [
        _snapshot("scan-one", "https://first.okta.com", token=token),
        _snapshot("scan-two", "https://first.okta.com", label="renamed", token=token),
    ]
    path = tmp_path / "graph.db"
    with open_graph_db(path) as conn:
        for graph in graphs:
            save_graph(conn, graph)
    with open_graph_db(path) as conn:
        restored = [load_graph(conn, tenant_id="tenant-one", scan_id=g.scan_id) for g in graphs]
        assert not load_graph(conn, tenant_id="tenant-two", scan_id="scan-one").nodes
    merged = _merge(*restored)
    identities = merged.nodes_by_type(EntityType.MANAGED_IDENTITY)
    assert len(identities) == 1
    assert identities[0].attributes["identity_id"] == "native-id"
    assert identities[0].attributes["correlation"]["source_scan_ids"] == ["scan-one", "scan-two"]
    assert len(identities[0].attributes["correlation"]["observations"]) == 2
    assert len(merged.nodes_by_type(EntityType.ACCOUNT)) == 1
    assert len([edge for edge in merged.edges if edge.relationship == RelationshipType.MEMBER_OF]) == 1


def test_identical_native_ids_in_different_orgs_do_not_correlate():
    merged = _merge(_snapshot("scan-one", "https://first.okta.com"), _snapshot("scan-two", "https://second.okta.com"))
    assert len(merged.nodes_by_type(EntityType.MANAGED_IDENTITY)) == 2
    assert len(merged.nodes_by_type(EntityType.ACCOUNT)) == 2


def test_identical_native_ids_of_different_kinds_do_not_correlate():
    merged = _merge(
        _snapshot("scan-one", "https://first.okta.com"),
        _snapshot("scan-two", "https://first.okta.com", token=True),
    )
    assert len(merged.nodes_by_type(EntityType.MANAGED_IDENTITY)) == 2
    assert len(merged.nodes_by_type(EntityType.ACCOUNT)) == 1


def test_missing_org_does_not_establish_cross_snapshot_identity(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_OKTA_ORG_URL", raising=False)
    merged = _merge(_snapshot("scan-one", ""), _snapshot("scan-two", ""))
    assert len(merged.nodes_by_type(EntityType.MANAGED_IDENTITY)) == 2
    assert not merged.nodes_by_type(EntityType.ACCOUNT)


@pytest.mark.parametrize("scope", ["local-org", "https://other.example", "https://first.okta.com/path", "https://first.okta.com/"])
def test_unverified_imported_scope_does_not_establish_cross_snapshot_identity(scope):
    from agent_bom.graph import UnifiedGraph
    from agent_bom.graph.nhi_overlay import apply_nhi_overlay
    from agent_bom.identity.okta_nhi import DiscoveredNonHumanIdentity

    graphs = []
    for scan in ("scan-one", "scan-two"):
        graph = UnifiedGraph(scan_id=scan, tenant_id="tenant-one")
        apply_nhi_overlay(
            graph,
            [
                DiscoveredNonHumanIdentity(
                    provider="okta", identity_id="native-id", identity_type="service_account", name="service", source_scope=scope
                )
            ],
        )
        graphs.append(graph)
    merged = _merge(*graphs)
    assert len(merged.nodes_by_type(EntityType.MANAGED_IDENTITY)) == 2
    assert len(merged.nodes_by_type(EntityType.ACCOUNT)) == 2
