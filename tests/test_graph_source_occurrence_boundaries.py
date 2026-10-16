"""Display labels and shared artifacts do not establish occurrence identity."""

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType


def test_dataset_cards_keep_source_version_and_conflicting_observations():
    records = [
        {"name": "training", "source_file": "one/card.md", "source_url": "https://one.example/data", "version": "1", "license": "MIT"},
        {
            "name": "training",
            "source_file": "two/card.md",
            "source_url": "https://two.example/data",
            "version": "1",
            "license": "restricted",
        },
        {"name": "training", "source_file": "one/card.md", "source_url": "https://one.example/data", "version": "2", "license": "MIT"},
    ]
    for ordered in (records, list(reversed(records))):
        graph = build_unified_graph_from_report({"dataset_cards": {"datasets": ordered + ordered[:1]}})
        nodes = list(graph.nodes_by_type(EntityType.DATASET))
        assert len(nodes) == 3
        assert {(n.attributes["source_file"], n.attributes["version"], n.attributes["license"]) for n in nodes} == {
            (r["source_file"], r["version"], r["license"]) for r in records
        }


def test_serving_configs_sharing_an_image_are_distinct_configured_occurrences():
    records = [
        {
            "name": "prod",
            "container_image": "serve:1",
            "source_file": "prod.yaml",
            "endpoint_url": "https://prod.example",
            "security_flags": ["no-auth"],
        },
        {
            "name": "dev",
            "container_image": "serve:1",
            "source_file": "dev.yaml",
            "endpoint_url": "https://dev.example",
            "security_flags": [],
        },
    ]
    graph = build_unified_graph_from_report({"serving_configs": records})
    nodes = list(graph.nodes_by_type(EntityType.CONTAINER))
    assert len(nodes) == 2
    assert {n.attributes["source_file"] for n in nodes} == {"prod.yaml", "dev.yaml"}
    assert all(n.attributes["runtime_identity_proven"] is False for n in nodes)


def test_runtime_label_targets_do_not_join_agents_or_case_distinct_labels():
    records = [
        {
            "schema_version": "runtime_incident_feedback.v1",
            "agent_id": agent,
            "kind": "reached_credential",
            "observed_at": "2026-10-16T00:00:00Z",
            "observed_tool_labels": labels,
        }
        for agent, labels in [("one", ["Read", "read"]), ("two", ["Read"])]
    ]
    graph = build_unified_graph_from_report(
        {"agents": [{"name": name, "mcp_servers": []} for name in ("one", "two")], "runtime_incident_feedback": records}
    )
    nodes = list(graph.nodes_by_type(EntityType.TOOL))
    assert len(nodes) == 3
    assert all(n.attributes["inventory_identity_proven"] is False for n in nodes)
    assert all(len({e.source for e in graph.edges_to(n.id)}) == 1 for n in nodes)


def test_model_provider_and_uri_scope_are_not_erased():
    from agent_bom.graph.training_projection import _model_node_id

    graph = build_unified_graph_from_report(
        {
            "model_provenance": [{"model_name": "openai/custom", "hash": "one"}, {"model_name": "azure/custom", "hash": "two"}],
            "serving_configs": [{"container_image": "serve:1", "model_uri": "s3://unrelated/custom"}],
        }
    )
    assert _model_node_id("openai/custom") != _model_node_id("azure/custom")
    assert len(list(graph.nodes_by_type(EntityType.MODEL))) == 2
    assert not [edge for edge in graph.edges if edge.relationship.value == "serves_model"]
