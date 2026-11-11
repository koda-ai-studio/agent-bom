"""``serving_evidence`` reaches the stored graph, the asset API, the MCP tool and the HTML report.

Every surface keeps runtime, endpoint, model artifact and collection evidence as
separate fields and lists what was not collected; nothing is installed or run.
"""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_graph_store
from agent_bom.cloud.serving_runtimes import NOT_COLLECTED
from agent_bom.mcp_tools.inventory import inventory_asset_impl
from tests._serving_runtime_fixtures import SCENARIOS, serving_fixture
from tests._serving_scan_helpers import scan_serving, scan_serving_report, serving_agent_ids, store_report

_SECTIONS = {"runtime", "endpoint", "model", "unknown_identities", "collection"}


@pytest.fixture(autouse=True)
def _job_store(monkeypatch):
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())


@pytest.fixture
def stored(tmp_path):
    """One vLLM scan stored for the default tenant and a TGI scan for tenant-b.

    The default model name has no ``/``: Starlette's TestClient decodes the
    request path twice, so a ``%2F`` inside an asset id cannot round-trip here.
    """
    with serving_fixture(SCENARIOS["vllm"]["success"]) as vllm_url:
        default_report = scan_serving_report(tmp_path, [f"vllm={vllm_url}"])
    with serving_fixture(SCENARIOS["tgi"]["success"]) as tgi_url:
        other_report = scan_serving_report(tmp_path, [f"tgi={tgi_url}"])
    store = SQLiteGraphStore(tmp_path / "graph.db")
    default_graph = store_report(store, default_report, scan_id="serving-default")
    other_graph = store_report(store, other_report, scan_id="serving-b", tenant_id="tenant-b")
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        yield store, default_graph, other_graph, vllm_url
    finally:
        set_graph_store(original)


def test_agent_node_carries_the_evidence_unchanged(stored):
    _store, graph, _other, url = stored
    (node_id,) = serving_agent_ids(graph).values()
    evidence = graph.nodes[node_id].attributes["serving_evidence"]
    assert set(evidence) == _SECTIONS
    assert evidence["runtime"] == {"name": "vllm", "version": "0.11.0", "identity": "confirmed"}
    assert evidence["endpoint"]["url"] == url
    assert evidence["model"]["artifact_ref"] == "Qwen/Qwen2.5-0.5B-Instruct"


def test_asset_detail_exposes_typed_sections_and_honest_gaps(stored):
    _store, graph, _other, url = stored
    (node_id,) = serving_agent_ids(graph).values()
    response = TestClient(app).get(f"/v1/inventory/assets/{quote(node_id, safe='')}")
    assert response.status_code == 200
    evidence = response.json()["serving_evidence"]
    assert set(evidence) == _SECTIONS
    assert evidence["runtime"]["name"] == "vllm"
    assert evidence["endpoint"] == {"url": url, "host": "127.0.0.1", "port": int(url.rsplit(":", 1)[1])}
    assert evidence["model"]["served_name"] == "qwen2.5-0.5b-instruct"
    assert evidence["model"]["artifact_ref"] == "Qwen/Qwen2.5-0.5B-Instruct"
    assert evidence["model"]["digest"] is None
    assert evidence["collection"]["status"] == "success"
    assert evidence["collection"]["request_identity"] == "anonymous"
    assert evidence["collection"]["not_collected"] == list(NOT_COLLECTED)
    assert evidence["unknown_identities"] == {"container": None, "gpu": None, "calling_agent": None, "principal": None}


def test_asset_without_serving_evidence_reports_null_not_empty(stored):
    _store, graph, _other, _url = stored
    (node_id,) = serving_agent_ids(graph).values()
    provider_id = next(edge.source for edge in graph.edges if edge.target == node_id and edge.source.startswith("provider:"))
    body = TestClient(app).get(f"/v1/inventory/assets/{quote(provider_id, safe='')}").json()
    assert body["serving_evidence"] is None


def test_asset_detail_is_tenant_scoped(stored):
    _store, _graph, other_graph, _url = stored
    (other_id,) = serving_agent_ids(other_graph).values()
    assert TestClient(app).get(f"/v1/inventory/assets/{quote(other_id, safe='')}").status_code == 404


@pytest.mark.asyncio
async def test_mcp_inventory_asset_matches_the_api(stored):
    store, graph, _other, _url = stored
    (node_id,) = serving_agent_ids(graph).values()
    api_body = TestClient(app).get(f"/v1/inventory/assets/{quote(node_id, safe='')}").json()
    mcp_body = json.loads(await inventory_asset_impl(asset_id=node_id, _get_graph_store=lambda: store, _truncate_response=lambda v: v))
    assert mcp_body["serving_evidence"] == api_body["serving_evidence"]
    hidden = json.loads(
        await inventory_asset_impl(
            asset_id=next(iter(serving_agent_ids(stored[2]).values())), _get_graph_store=lambda: store, _truncate_response=lambda v: v
        )
    )
    assert hidden["error"]["category"] == "not_found"


def test_html_report_renders_each_evidence_section(tmp_path):
    with serving_fixture(SCENARIOS["triton"]["success"]) as url:
        out, _output = scan_serving(tmp_path, [f"triton={url}"], fmt="html")
    html = out.read_text()
    assert html.count('class="serving-evidence"') == 2
    for label in ("Runtime", "Endpoint", "Model artifact", "Collection", "Not collected"):
        assert f"<dt>{label}</dt>" in html
    assert "triton 2.59.0 (confirmed)" in html
    assert f"{url}" in html
    assert "densenet_onnx" in html
    assert "version 1" in html
    assert "success &middot; complete" in html
    assert "bind_address, public_reachability, tls, authentication" in html
    assert "container, gpu, calling_agent, principal" in html


def test_html_escapes_endpoint_reported_names(tmp_path):
    routes = {("GET", "/v1/models"): (200, {"object": "list", "data": [{"id": "<img src=x onerror=alert(1)>", "owned_by": "vllm"}]}, 0.0)}
    with serving_fixture(routes) as url:
        out, _output = scan_serving(tmp_path, [f"vllm={url}"], fmt="html")
    html = out.read_text()
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_labels_unreported_values_instead_of_blank(tmp_path):
    with serving_fixture(SCENARIOS["lmstudio"]["success"]) as url:
        out, _output = scan_serving(tmp_path, [f"lmstudio={url}"], fmt="html")
    html = out.read_text()
    assert "lmstudio version not reported (confirmed)" in html
    assert "digest not reported" in html
