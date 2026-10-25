"""Persisted activity is recorded evidence, never inferred tool execution."""

from dataclasses import replace

import pytest

from agent_bom.api import gateway_activity_store as gateway
from agent_bom.api.observability_events import _normalize_ocsf_event, _runtime_observation_from_event
from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore
from agent_bom.api.trace_collection.trace_evidence import with_trace_events
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

START = "2026-10-01T00:00:00+00:00"
END = "2026-10-20T00:00:00+00:00"
STAMP = "2026-10-15T00:00:00+00:00"


def _ocsf(event_id="ocsf-one", account="account-a"):
    return {
        "metadata": {"uid": event_id, "product": {"name": "fixture-sensor"}},
        "class_name": "API Activity",
        "time": STAMP,
        "cloud": {"provider": "aws", "account": {"uid": account}},
        "resources": [{"name": "query"}],
        "unmapped": {"agent_bom.agent_ref": "agent:one", "agent_bom.inventory_node_id": "tool:one"},
    }


def _gateway(event_id="gateway-one", stamp=STAMP, tenant="tenant-a"):
    record = gateway.GatewayActivityRecord(
        tenant_id=tenant,
        event_id=event_id,
        decision_id=event_id,
        event_type="gateway.tool_call.blocked",
        event_schema_version="gateway.runtime.event.v1",
        event_timestamp=stamp,
        ingested_at=STAMP,
        source_id="fixture-gateway",
        session_id="session-one",
        agent_id="agent:one",
        upstream="server:one",
        tool="query",
        decision="deny",
        policy_source="fixture-policy",
        trace_id="trace-one",
    )
    return replace(record, event_digest=gateway._digest_payload(record))


@pytest.fixture
def stores(monkeypatch):
    runtime = InMemoryRuntimeEventStore()
    ledger = gateway.InMemoryGatewayActivityStore()
    monkeypatch.setattr(gateway, "_GATEWAY_ACTIVITY_STORE", ledger)
    return runtime, ledger


def test_persisted_ocsf_and_gateway_enter_the_graph_without_trace_opt_in(stores, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_EXPERIMENTAL", raising=False)
    runtime, ledger = stores
    record = _runtime_observation_from_event(_normalize_ocsf_event(_ocsf(), tenant_id="tenant-a"), tenant_id="tenant-a")
    runtime.put_observation(record)
    runtime.put_observation(replace(record, tenant_id="tenant-b", observation_id="other-tenant"))
    ledger.append_batch([_gateway()])
    ledger.append_batch([_gateway("other-gateway", tenant="tenant-b")])
    report = with_trace_events({"scan_timestamp": END}, "tenant-a", store=runtime)
    graph = build_unified_graph_from_report(report, scan_id="scan-one", tenant_id="tenant-a")
    edges = [e for e in graph.edges if e.relationship.value == "recorded_activity"]
    assert len(edges) == 2, "both persisted sources must produce explicit recorded activity"
    receipts = [r for e in edges for r in e.evidence["receipts"]]
    assert {r["event_id"] for r in receipts} == {"ocsf-one", "gateway-one"}
    assert {r["surface"] for r in receipts} == {"runtime", "gateway"}
    assert all(not e.traversable and e.evidence["tier"] == "recorded" for e in edges)
    assert all(e.evidence["execution_confirmed"] is False for e in edges)
    assert all(graph.has_node(e.source) and graph.has_node(e.target) for e in edges)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_gateway_window_is_tenant_scoped_and_filters_before_the_budget(backend, tmp_path):
    ledger = (
        gateway.InMemoryGatewayActivityStore() if backend == "memory" else gateway.SQLiteGatewayActivityStore(str(tmp_path / "ledger.db"))
    )
    ledger.append_batch(
        [_gateway("old"), _gateway("a", END), _gateway("b", "2026-10-19T20:00:00-04:00"), _gateway("new", "2026-10-25T00:00:00Z")]
    )
    ledger.append_batch([_gateway("other", tenant="tenant-b")])
    window = getattr(ledger, "window_activity", None)
    assert callable(window), "gateway graph reads need a time-first keyset window"
    first = window("tenant-a", window_start=START, window_end=END, limit=2)
    assert [r.event_id for r in first] == ["b", "a"]
    last = first[-1]
    second = window("tenant-a", window_start=START, window_end=END, limit=2, before=(last.event_timestamp, last.event_id))
    assert [r.event_id for r in second] == ["old"]


def test_ocsf_retains_explicit_graph_refs_separate_from_actor_display_fields():
    event = _normalize_ocsf_event(_ocsf(), tenant_id="tenant-a")
    assert event.get("graph_context") == {"agent_ref": "agent:one", "target_ref": "tool:one", "account_ref": "account-a", "provider": "aws"}


@pytest.mark.parametrize("account,exact", [("account-a", True), ("account-b", False), ("", False)])
def test_activity_binding_rejects_cross_account_and_missing_cloud_scope(stores, account, exact):
    runtime, _ = stores
    runtime.put_observation(
        _runtime_observation_from_event(_normalize_ocsf_event(_ocsf(account=account), tenant_id="tenant-a"), tenant_id="tenant-a")
    )
    payload = with_trace_events({"scan_timestamp": END}, "tenant-a", store=runtime).get("runtime_activity_events")
    assert payload is not None, "persisted runtime evidence must reach the projection"
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant-a")
    for ref, kind in [("agent:one", EntityType.AGENT), ("tool:one", EntityType.TOOL)]:
        graph.add_node(
            UnifiedNode(id=ref, entity_type=kind, label="same-name", attributes={"account_ref": "account-a", "cloud_provider": "aws"})
        )
    project_recorded_activity(graph, payload, "tenant-a")
    edge = next(e for e in graph.edges if e.relationship.value == "recorded_activity")
    assert (edge.source == "agent:one" and edge.target == "tool:one") is exact
    assert not edge.traversable


def _projection_payload(**changes):
    event = {
        "tenant_id": "tenant-a",
        "event_id": "one",
        "source": "fixture",
        "surface": "runtime",
        "observed_at": STAMP,
        "agent_ref": "agent:one",
        "target_ref": "tool:one",
        "agent_name": "same",
        "target_name": "query",
        **changes,
    }
    return {"window_start": START, "window_end": END, "events": [event]}


def _inventory():
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant-a")
    graph.add_node(UnifiedNode(id="agent:one", entity_type=EntityType.AGENT, label="same"))
    graph.add_node(UnifiedNode(id="tool:one", entity_type=EntityType.TOOL, label="query"))
    return graph


@pytest.mark.parametrize("field", ["source", "event_id", "agent_ref", "account_ref", "surface"])
def test_malformed_activity_identity_is_rejected_without_crashing(field):
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    project_recorded_activity(graph, _projection_payload(**{field: {"untrusted": "mapping"}}), "tenant-a")
    assert not graph.edges
    assert graph.analysis_status["runtime_activity_projection"].observed["rejected"] == 1


def test_long_reference_never_binds_to_a_truncated_identifier():
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    prefix = "agent:" + "a" * 506
    graph.add_node(UnifiedNode(id=prefix, entity_type=EntityType.AGENT, label="prefix"))
    project_recorded_activity(graph, _projection_payload(agent_ref=prefix + "-different"), "tenant-a")
    assert all(edge.source != prefix for edge in graph.edges)


def test_native_cloud_scope_is_required_even_when_only_arn_is_recorded():
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    graph.get_node("agent:one").attributes["arn"] = "arn:aws:lambda:us-east-1:111111111111:function:fixture"
    project_recorded_activity(graph, _projection_payload(), "tenant-a")
    assert all(edge.source != "agent:one" for edge in graph.edges)


def test_shared_cap_is_visible_and_gateway_failure_keeps_other_evidence(stores, monkeypatch):
    from agent_bom.api.trace_collection import runtime_evidence

    runtime, ledger = stores
    runtime.put_observation(_runtime_observation_from_event(_normalize_ocsf_event(_ocsf(), tenant_id="tenant-a"), tenant_id="tenant-a"))
    ledger.append_batch([_gateway(stamp=END)])
    monkeypatch.setattr(runtime_evidence, "MAX_WINDOW_EVENTS", 1)
    report = with_trace_events({"scan_timestamp": END}, "tenant-a", store=runtime)
    payload = report["runtime_activity_events"]
    assert len(payload["events"]) == 1 and payload["events"][0]["event_id"] == "gateway-one"
    assert payload["load_truncated"] is True
    graph = build_unified_graph_from_report(report, scan_id="scan", tenant_id="tenant-a")
    assert "load_cap" in graph.analysis_status["runtime_activity_projection"].reason_codes

    def broken(*args, **kwargs):
        raise RuntimeError("private-connection-details")

    monkeypatch.setattr(ledger, "window_activity", broken)
    report = with_trace_events({"scan_timestamp": END}, "tenant-a", store=runtime)
    payload = report["runtime_activity_events"]
    assert [event["event_id"] for event in payload["events"]] == ["ocsf-one"]
    assert payload["load_failures"] == ["gateway_store_unavailable"]
    assert "private-connection-details" not in str(report)


def test_replay_is_idempotent_and_recorded_edges_cannot_establish_reachability():
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    payload = _projection_payload(prompt="untrusted-private-prompt")
    payload["events"] *= 2
    project_recorded_activity(graph, payload, "tenant-a")
    edge = graph.edges[0]
    assert edge.source == "agent:one" and edge.target == "tool:one"
    assert edge.evidence["event_count"] == 1
    assert len(edge.evidence["receipts"]) == 1
    assert "untrusted-private-prompt" not in str(edge.to_dict())
    assert graph.bfs("agent:one", traversable_only=True) == []
    assert ["agent:one", "tool:one"] in graph.bfs("agent:one", traversable_only=False)


def test_proxy_and_gateway_observations_share_the_window(stores):
    runtime, _ = stores
    record = _runtime_observation_from_event(_normalize_ocsf_event(_ocsf(), tenant_id="tenant-a"), tenant_id="tenant-a")
    for surface in ("runtime", "proxy", "gateway"):
        runtime.put_observation(replace(record, observation_id=surface, surface=surface))
    report = with_trace_events({"scan_timestamp": END}, "tenant-a", store=runtime)
    assert {event["surface"] for event in report["runtime_activity_events"]["events"]} == {"runtime", "proxy", "gateway"}


def test_gateway_initialization_failure_preserves_runtime_evidence(stores, monkeypatch):
    from agent_bom.api.trace_collection import trace_evidence

    runtime, _ = stores
    runtime.put_observation(_runtime_observation_from_event(_normalize_ocsf_event(_ocsf(), tenant_id="tenant-a"), tenant_id="tenant-a"))

    def fail():
        raise RuntimeError("private provider connection detail")

    monkeypatch.setattr(trace_evidence, "get_gateway_activity_store", fail)
    report = with_trace_events({"scan_timestamp": END}, "tenant-a", store=runtime)
    assert [event["event_id"] for event in report["runtime_activity_events"]["events"]] == ["ocsf-one"]
    assert report["runtime_activity_events"]["load_failures"] == ["gateway_store_unavailable"]


def test_native_provider_disagreement_never_binds():
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    graph.get_node("agent:one").attributes["arn"] = "arn:aws:lambda:us-east-1:111111111111:function:fixture"
    project_recorded_activity(graph, _projection_payload(account_ref="111111111111", provider="azure"), "tenant-a")
    assert all(edge.source != "agent:one" for edge in graph.edges)


def test_activity_times_are_utc_ordered_and_reprojection_preserves_receipts():
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    first = _projection_payload(observed_at="2026-10-15T01:00:00+02:00")
    first["events"].append({**first["events"][0], "event_id": "two", "observed_at": STAMP})
    project_recorded_activity(graph, first, "tenant-a")
    edge = graph.edges[0]
    assert edge.first_seen == "2026-10-14T23:00:00+00:00"
    assert edge.last_seen == STAMP
    project_recorded_activity(graph, _projection_payload(event_id="three", observed_at=END), "tenant-a")
    project_recorded_activity(graph, first, "tenant-a")
    assert len(graph.edges) == 1
    assert {r["event_id"] for r in edge.evidence["receipts"]} == {"one", "two", "three"}
    assert edge.evidence["event_count"] == 3
    assert edge.last_seen == END
    restored = UnifiedGraph.from_dict(graph.to_dict())
    assert restored.edges[0].evidence == edge.evidence
    assert not restored.edges[0].traversable


def test_foreign_tenant_payload_never_creates_nodes():
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    project_recorded_activity(graph, _projection_payload(tenant_id="tenant-b"), "tenant-a")
    assert not graph.edges and len(graph.nodes) == 2


def test_reported_cloud_provider_cannot_borrow_unscoped_inventory():
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    project_recorded_activity(graph, _projection_payload(provider="aws"), "tenant-a")
    assert all(edge.source != "agent:one" and edge.target != "tool:one" for edge in graph.edges)


def test_matching_native_owner_and_provider_can_bind():
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    graph.get_node("agent:one").attributes["arn"] = "arn:aws:lambda:us-east-1:111111111111:function:fixture"
    project_recorded_activity(graph, _projection_payload(account_ref="111111111111", provider="aws"), "tenant-a")
    assert graph.edges[0].source == "agent:one"


def test_persisted_graph_coordinate_survives_field_sensitive_redaction():
    target = "tool:server:cfg-862185e36f77:bridge-fixture:111c239b-bb2c-530c-bebb-82ef9842e23b:query"
    event = _ocsf()
    event["unmapped"]["agent_bom.inventory_node_id"] = target
    record = _runtime_observation_from_event(_normalize_ocsf_event(event, tenant_id="tenant-a"), tenant_id="tenant-a")
    assert record.metadata["graph_context"]["target_ref"] == target


@pytest.mark.parametrize("field", ["agent_ref", "target_ref", "upstream_ref"])
def test_graph_reference_fields_still_redact_embedded_credentials(field):
    from agent_bom.security import sanitize_sensitive_payload

    token = "ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"
    value = "tool:server:" + token + ":query"
    assert token not in str(sanitize_sensitive_payload({field: value}))


def test_metadata_never_turns_a_long_graph_reference_into_a_shorter_identity():
    target = "tool:" + "a" * 496
    record = _runtime_observation_from_event(
        {"event_id": "long-coordinate", "observed_at": STAMP, "metadata": {"graph_context": {"target_ref": target}}},
        tenant_id="tenant-a",
    )
    assert "target_ref" not in record.metadata["graph_context"]


def test_recorded_activity_is_in_runtime_views_without_becoming_traversable(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph.activity_projection import project_recorded_activity

    graph = _inventory()
    project_recorded_activity(graph, _projection_payload(), "tenant-a")
    assert len(graph.runtime_view().edges) == 1
    assert len(graph.filter_edges(dynamic_only=True)) == 1
    assert not graph.filter_edges(static_only=True)
    assert not graph.filter_edges(traversable_only=True)
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(graph)
    for backend in (graph, store):
        scope = {} if backend is graph else {"tenant_id": "tenant-a", "scan_id": "scan"}
        dynamic, _, _ = backend.traverse_subgraph(roots=["agent:one"], dynamic_only=True, **scope)
        static, _, _ = backend.traverse_subgraph(roots=["agent:one"], static_only=True, **scope)
        attack, _, _ = backend.traverse_subgraph(roots=["agent:one"], dynamic_only=True, traversable_only=True, **scope)
        assert len(dynamic.edges) == 1
        assert not static.edges
        assert not attack.edges
