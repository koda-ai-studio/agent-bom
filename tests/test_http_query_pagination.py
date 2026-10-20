"""Preserve provider query strings through the synchronous HTTP transport."""

import httpx
import pytest

from agent_bom import http_client
from agent_bom.identity.entra_nhi import EntraClient


@pytest.fixture
def mock_transport(monkeypatch):
    def install(handler):
        monkeypatch.setattr(
            http_client,
            "create_sync_client",
            lambda **kwargs: httpx.Client(transport=httpx.MockTransport(handler)),
        )

    return install


def test_fetch_json_preserves_embedded_filter_and_encoded_cursor(mock_transport):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"value": []})

    mock_transport(handle)
    http_client.fetch_json("https://graph.microsoft.com/v1.0/servicePrincipals?$top=2&$skiptoken=next%2Bpage%3D&$select=id")
    assert dict(requests[0].url.params) == {"$top": "2", "$skiptoken": "next+page=", "$select": "id"}


def test_retry_keeps_the_same_provider_cursor(mock_transport, monkeypatch):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(503 if len(requests) == 1 else 200, json={"value": []})

    mock_transport(handle)
    monkeypatch.setattr(http_client.time, "sleep", lambda _: None)
    http_client.fetch_json("https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=second-page")
    assert len(requests) == 2
    assert all(request.url.params.get("$skiptoken") == "second-page" for request in requests)


def test_entra_continuation_reads_each_page_once(mock_transport):
    requests = []

    def handle(request):
        requests.append(request)
        assert len(requests) <= 2, "Pagination repeated page one instead of following its continuation token"
        if request.url.params.get("$skiptoken") == "page-two":
            return httpx.Response(200, json={"value": [{"id": "principal-two"}]})
        return httpx.Response(
            200,
            json={
                "value": [{"id": "principal-one"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=page-two",
            },
        )

    mock_transport(handle)
    principals = EntraClient("synthetic-bearer").list_service_principals()
    assert [principal["id"] for principal in principals] == ["principal-one", "principal-two"]
    assert len(requests) == 2
    assert all(request.headers["Authorization"] == "Bearer synthetic-bearer" for request in requests)


@pytest.mark.parametrize("params", [{"page": "explicit"}, {}])
def test_explicit_query_params_keep_httpx_replacement_semantics(mock_transport, params):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={})

    mock_transport(handle)
    response = http_client.sync_get("https://api.example.test/items?page=embedded", params=params)
    assert response is not None and response.status_code == 200
    assert dict(requests[0].url.params) == params
