"""New read routes reject undeclared query parameters instead of silently ignoring them."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app, configure_api
from tests.auth_helpers import PROXY_SECRET, proxy_headers

HEADERS = proxy_headers()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        configure_api(api_key=None)


@pytest.mark.parametrize(
    "path",
    [
        "/v1/findings?kev_only=true",
        "/v1/findings?group_occurrences=true&unknown_filter=high",
        "/v1/intel/advisories/CVE-2026-0001/affected?verdict_=affected",
        "/v1/graph/attack-paths/cross-vendor?source_vendors=aws",
    ],
)
def test_misspelled_filter_is_a_422_not_an_unfiltered_page(client: TestClient, path: str) -> None:
    response = client.get(path, headers=HEADERS)
    assert response.status_code == 422, response.text
    assert "Unknown query parameter" in response.text
