"""Consequence responses are authenticated, tenant-bound and generation-pinned."""

import pytest

from tests.test_graph_tenant_scope_and_bounds import _path_graph, api  # noqa: F401


def body(**changes):
    return {"root_node_id": "principal:reader", "scan_id": "shared-scan", "mode": "assumed_compromise", "assume_control": True, **changes}


def test_consequence_is_a_pinned_read(api):  # noqa: F811
    client, _, headers = api
    result = client.post("/v1/graph/consequences", json=body(), headers=headers["tenant-a"])
    assert result.status_code == 200, result.text
    payload = result.json()
    assert payload["snapshot_generation"] and payload["tenant_id"] == "tenant-a"
    assert payload["current_access"] == "not_evaluated" and payload["capability"] == "experimental"
    assert payload["consequences"][0]["status"] == "unknown"


def test_consequence_anonymous_and_tenant_override_rejected(api):  # noqa: F811
    client, _, headers = api
    assert client.post("/v1/graph/consequences", json=body()).status_code == 401
    assert client.post("/v1/graph/consequences", json=body(tenant_id="tenant-b"), headers=headers["tenant-a"]).status_code == 422


def test_consequence_replacement_and_cross_tenant_revision_rejected(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    first = client.post("/v1/graph/consequences", json=body(), headers=headers["tenant-a"])
    revision = first.json()["snapshot_generation"]
    assert client.post("/v1/graph/consequences", json=body(snapshot_generation=revision), headers=headers["tenant-b"]).status_code == 409
    original = store.traverse_subgraph

    def replace(**kwargs):
        result = original(**kwargs)
        store.save_graph(_path_graph("tenant-a"))
        return result

    monkeypatch.setattr(store, "traverse_subgraph", replace)
    assert client.post("/v1/graph/consequences", json=body(), headers=headers["tenant-a"]).status_code == 409


def test_consequence_uses_bounded_storage_and_marks_partial_unknown(api, monkeypatch):  # noqa: F811
    client, store, headers = api

    def forbidden(**kwargs):
        pytest.fail("no unbounded estate loads")

    monkeypatch.setattr(store, "load_graph", forbidden)
    original = store.traverse_subgraph

    def partial(**kwargs):
        assert kwargs["max_nodes"] <= 4096 and kwargs["max_edges"] <= 8192
        graph, depths, _ = original(**kwargs)
        graph.completeness.truncated = True
        return graph, depths, True

    monkeypatch.setattr(store, "traverse_subgraph", partial)
    result = client.post("/v1/graph/consequences", json=body(), headers=headers["tenant-a"])
    assert result.status_code == 200
    assert result.json()["truncated"] and result.json()["counts"]["lower_bound"]
    assert result.json()["counts"]["supported"] == 0
