"""/v1/registry pages, searches and filters the MCP catalog server-side.

The catalog page used to download the whole bundled registry (~1 MB) on
every visit and filter it in the browser. A bounded request returns one page,
the matching total and the facet counts the filter controls need.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api.server import _load_registry, app


@pytest.fixture()
def client() -> TestClient:
    _load_registry.cache_clear()
    return TestClient(app)


def test_bounded_page_with_totals_and_population_counts(client: TestClient) -> None:
    catalog = _load_registry()
    body = client.get("/v1/registry?limit=25").json()

    assert len(body["servers"]) == 25
    assert body["count"] == len(catalog)
    assert body["total"] == len(catalog)
    assert body["has_more"] is True
    assert body["next_cursor"] == "25"
    assert sum(body["risk_counts"].values()) == len(catalog)
    assert body["risk_counts"]["high"] == len([s for s in catalog if s["risk_level"] == "high"])
    assert len(client.get("/v1/registry?limit=25").content) < 100_000


def test_search_risk_and_category_filters_apply_server_side(client: TestClient) -> None:
    catalog = _load_registry()
    category = next(s["category"] for s in catalog if s.get("category") and s["risk_level"] == "high")
    body = client.get("/v1/registry", params={"limit": 100, "risk": "high", "category": category}).json()

    expected = [s for s in catalog if s["risk_level"] == "high" and s.get("category") == category]
    assert body["total"] == len(expected)
    assert all(s["risk_level"] == "high" and s["category"] == category for s in body["servers"])
    # The risk facet ignores the risk selection so other levels stay choosable.
    assert body["facets"]["risk_level"]["high"] == len(expected)
    assert sum(body["facets"]["risk_level"].values()) == len([s for s in catalog if s.get("category") == category])
    assert category in body["facets"]["category"]

    search = client.get("/v1/registry", params={"limit": 10, "q": "FILESYSTEM"}).json()
    assert "@modelcontextprotocol/server-filesystem" in {s["id"] for s in search["servers"]}


def test_params_are_bounded(client: TestClient) -> None:
    assert client.get("/v1/registry?limit=0").status_code == 422
    assert client.get("/v1/registry?limit=501").status_code == 422
    assert client.get("/v1/registry?offset=-1").status_code == 422
    assert client.get("/v1/registry?risk=severe").status_code == 422
    assert client.get("/v1/registry", params={"q": "x" * 201}).status_code == 422


def test_legacy_call_still_returns_the_whole_catalog(client: TestClient) -> None:
    body = client.get("/v1/registry").json()

    assert body["count"] == len(body["servers"]) == len(_load_registry())
    assert body["has_more"] is False
