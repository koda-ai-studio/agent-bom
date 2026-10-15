"""``/v1/graph/schema`` reports the same producers as the generated data-model docs."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.graph.emitter_scan import production_emitters


def _schema() -> dict:
    return TestClient(app).get("/v1/graph/schema").json()


def test_every_scanned_relationship_producer_is_reported_emitted() -> None:
    edges = {edge["key"]: edge for edge in _schema()["edge_kinds"]}
    scanned = production_emitters(relationships=True)
    assert scanned
    for rel, modules in scanned.items():
        assert edges[rel]["emission_status"] == "emitted", rel
        assert edges[rel]["emission_surfaces"] == modules, rel


def test_every_scanned_entity_producer_is_reported_emitted() -> None:
    nodes = {node["key"]: node for node in _schema()["node_kinds"]}
    for entity, modules in production_emitters(relationships=False).items():
        assert nodes[entity]["emission_status"] == "emitted", entity
        assert nodes[entity]["emission_surfaces"] == modules, entity


def test_known_drift_cases_are_reported_from_the_scan() -> None:
    edges = {edge["key"]: edge for edge in _schema()["edge_kinds"]}
    assert edges["hosted_on"]["emission_status"] == "emitted"
    assert "graph/hosting_projection.py" in edges["hosted_on"]["emission_surfaces"]
    assert "graph/asset_canonicalize.py" in edges["possibly_correlates_with"]["emission_surfaces"]


def test_kinds_without_producers_stay_reserved() -> None:
    scanned = production_emitters(relationships=True)
    for edge in _schema()["edge_kinds"]:
        if edge["key"] not in scanned:
            assert edge["emission_status"] == "reserved", edge["key"]
