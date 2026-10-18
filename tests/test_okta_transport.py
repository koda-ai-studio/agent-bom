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
        r"https://evil.com\.okta.com",
        "https://%2f.okta.com",
        "https://.okta.com",
        "https://a..okta.com",
        "https://-a.okta.com",
        "https://a-.okta.com",
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


@pytest.mark.parametrize("bound", ["MAX_RECORDS", "MAX_PAGES"])
def test_bounded_discovery_retains_validated_apps_with_partial_receipt(monkeypatch, bound):
    from agent_bom.identity.okta_nhi import discover_okta_non_human_identities

    monkeypatch.setattr("agent_bom.identity.okta_http." + bound, 1)
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path.endswith("api-tokens"):
            return httpx.Response(200, json=[])
        apps = [
            {
                "id": "one",
                "label": "service",
                "signOnMode": "OPENID_CONNECT",
                "credentials": {"oauthClient": {"token_endpoint_auth_method": "private_key_jwt"}},
                "settings": {"oauthClient": {"grant_types": ["client_credentials"]}},
            }
        ]
        if bound == "MAX_RECORDS":
            apps.append({**apps[0], "id": "two"})
        return httpx.Response(200, json=apps, headers={"Link": '<https://example.okta.com/api/v1/apps?after=a>; rel="next"'})

    client = OktaClient("https://example.okta.com", "fixture", transport=httpx.MockTransport(handler))
    result = discover_okta_non_human_identities(org_url="https://example.okta.com", client=client)
    assert result.status.value == "partial"
    assert len(result.identities) == 1
    assert result.coverage[0]["state"] == "partial"
    assert result.coverage[0]["reason_code"] == ("record_limit" if bound == "MAX_RECORDS" else "page_limit")
    assert result.coverage[0]["count"] == 1
