"""Credential confinement and complete, bounded Okta metadata collection."""

import httpx
import pytest

from agent_bom.identity.okta_nhi import OktaClient


def test_follows_same_endpoint_pagination():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["authorization"] == "SSWS fixture-token"
        if len(requests) == 1:
            return httpx.Response(200, json=[{"id": "a"}], headers={"Link": '<https://example.okta.com/api/v1/apps?after=a>; rel="next"'})
        return httpx.Response(200, json=[{"id": "b"}])

    client = OktaClient("https://example.okta.com", "fixture-token", transport=httpx.MockTransport(handler))
    assert [x["id"] for x in client.list_oauth2_service_apps()] == ["a", "b"]
    assert len(requests) == 2


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/api/v1/apps",
        "http://example.okta.com/api/v1/apps",
        "https://example.okta.com/api/v1/users",
        "https://user:pass@example.okta.com/api/v1/apps",
    ],
)
def test_rejects_pagination_destination_before_sending_auth(target):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=[{"id": "a"}], headers={"Link": f'<{target}>; rel="next"'})

    client = OktaClient("https://example.okta.com", "fixture-token", transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError):
        client.list_oauth2_service_apps()
    assert len(requests) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://example.okta.com",
        "https://example.okta.com.evil.com",
        "https://example.okta.com/path",
        "https://user:secret@example.okta.com",
        "https://127.0.0.1",
    ],
)
def test_invalid_org_rejected(url):
    with pytest.raises(ValueError):
        OktaClient(url, "fixture-token")


@pytest.mark.parametrize("payload", [{"error": "secret"}, [None], [{"name": "missing id"}], [{"id": "a"}, {"id": "a"}]])
def test_invalid_page_fails_closed(payload):
    client = OktaClient(
        "https://example.okta.com", "fixture-token", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
    )
    with pytest.raises(ValueError):
        client.list_api_tokens()


def test_redirect_not_followed():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.example"})

    client = OktaClient("https://example.okta.com", "fixture-token", transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError):
        client.list_api_tokens()
    assert len(calls) == 1


def test_pagination_bound_is_not_a_complete_inventory(monkeypatch):
    monkeypatch.setattr("agent_bom.identity.okta_http.MAX_PAGES", 2)
    calls = []

    def handler(request):
        calls.append(request)
        cursor = str(len(calls))
        return httpx.Response(
            200, json=[{"id": cursor}], headers={"Link": f'<https://example.okta.com/api/v1/apps?after={cursor}>; rel="next"'}
        )

    client = OktaClient("https://example.okta.com", "fixture", transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="bound"):
        client.list_oauth2_service_apps()
    assert len(calls) == 2


def test_response_byte_bound(monkeypatch):
    monkeypatch.setattr("agent_bom.identity.okta_http.MAX_BYTES", 8)
    client = OktaClient(
        "https://example.okta.com", "fixture", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[{"id": "too-long"}]))
    )
    with pytest.raises(ValueError, match="bound"):
        client.list_api_tokens()
