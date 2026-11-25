"""Merging observations cannot make older attribute values look newly observed."""

from itertools import permutations

from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.node_merge import merge_node
from agent_bom.graph.types import EntityType


def observation(at, value, source="inventory"):
    return UnifiedNode(
        id="asset",
        label="Asset",
        entity_type=EntityType.CLOUD_RESOURCE,
        first_seen=at,
        last_seen=at,
        attributes={"internet_exposed": value},
        data_sources=[source],
    )


def test_old_observation_cannot_replace_newer_value():
    current = observation("2026-11-25T00:00:00Z", False)
    merge_node(current, observation("2026-01-01T00:00:00Z", True))
    assert current.attributes["internet_exposed"] is False
    receipt = current.attributes["attribute_observations"]["internet_exposed"]
    assert receipt["observed_at"] == "2026-11-25T00:00:00+00:00"
    assert receipt["conflicted"] is True


def test_replay_order_and_serialization_preserve_selected_evidence():
    results = []
    rows = [("2026-01-01T00:00:00Z", True), ("2026-11-25T00:00:00Z", False), ("2026-02-01T00:00:00Z", None)]
    for order in permutations(rows):
        node = observation(*order[0])
        for row in order[1:]:
            node = UnifiedNode.from_dict(node.to_dict())
            merge_node(node, observation(*row))
        results.append(node.attributes)
    assert all(result == results[0] for result in results)
    assert results[0]["internet_exposed"] is False


def test_new_unknown_is_not_replaced_with_old_false():
    current = observation("2026-11-25T00:00:00Z", None)
    merge_node(current, observation("2026-01-01T00:00:00Z", False))
    assert current.attributes["internet_exposed"] is None


def test_receipts_survive_sqlite_and_tenant_boundaries(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph.container import UnifiedGraph

    store = SQLiteGraphStore(tmp_path / "observations.db")
    for tenant, value in [("a", True), ("b", False)]:
        graph = UnifiedGraph(scan_id="same", tenant_id=tenant)
        graph.add_node(observation("2026-11-25T00:00:00Z", value))
        graph.add_node(observation("2026-01-01T00:00:00Z", None))
        store.save_graph(graph)
    for tenant, value in [("a", True), ("b", False)]:
        graph = store.load_graph(scan_id="same", tenant_id=tenant)
        node = graph.nodes["asset"]
        assert node.attributes["internet_exposed"] is value
        receipt = node.attributes["attribute_observations"]["internet_exposed"]
        assert receipt["sources"] == ["inventory"]
        assert receipt["observed_at"] == "2026-11-25T00:00:00+00:00"


def test_equal_time_conflict_is_deterministic_and_visible():
    results = []
    for values in [(True, False), (False, True)]:
        node = observation("2026-11-25T00:00:00Z", values[0])
        merge_node(node, observation("2026-11-25T00:00:00Z", values[1]))
        results.append(node.attributes)
    assert results[0] == results[1]
    assert results[0]["attribute_observations"]["internet_exposed"]["conflicted"] is True


def test_malformed_prior_receipt_does_not_crash_merge():
    import hashlib

    node = observation("2026-11-25T00:00:00Z", False)
    node.attributes["attribute_observations"] = {
        "internet_exposed": {"value_digest": hashlib.sha256(b"false").hexdigest(), "observed_at": 42, "sources": 42, "conflicted": "no"}
    }
    merge_node(node, observation("2026-01-01T00:00:00Z", True))
    assert node.attributes["internet_exposed"] is False


def test_same_time_security_disagreement_retains_positive_risk():
    node = observation("2026-11-25T00:00:00Z", True)
    merge_node(node, observation("2026-11-25T00:00:00Z", False))
    assert node.attributes["internet_exposed"] is True
    assert node.attributes["attribute_observations"]["internet_exposed"]["conflicted"] is True


def test_subsecond_observation_order_is_preserved():
    node = observation("2026-11-25T00:00:00.900Z", False)
    merge_node(node, observation("2026-11-25T00:00:00.100Z", True))
    assert node.attributes["internet_exposed"] is False
    assert node.attributes["attribute_observations"]["internet_exposed"]["observed_at"] == "2026-11-25T00:00:00.900000+00:00"
