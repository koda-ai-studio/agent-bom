"""RunPod stages retain independent coverage on HTTP and GraphQL failures."""

import httpx
import pytest

from agent_bom.cloud import runpod


def _mock_responses(monkeypatch, first, second=None):
    replies = iter([first, second or {"data": {"myself": {"endpoints": [{"id": "endpoint-one", "name": "fixture"}]}}}])

    def request(*args, **kwargs):
        value = next(replies)
        if isinstance(value, httpx.Response):
            return value
        return httpx.Response(200, json=value, request=httpx.Request("POST", "https://example.test"))

    monkeypatch.setattr(runpod.http_client, "sync_request_with_retry", request)


@pytest.mark.parametrize("status,code", [(401, "denied"), (403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_http_failure_keeps_other_stage(monkeypatch, status, code):
    response = httpx.Response(status, text="private-marker", request=httpx.Request("POST", "https://example.test/private-marker"))
    _mock_responses(monkeypatch, response)
    agents, warnings = runpod.discover(api_key="fixture")
    assert [a.name for a in agents] == ["runpod-serverless:fixture"]
    assert len(warnings) == 1
    assert warnings[0].startswith(f"runpod:pods:{code}:")
    assert "private-marker" not in warnings[0]


@pytest.mark.parametrize(
    "code,expected",
    [("FORBIDDEN", "denied"), ("UNAUTHENTICATED", "denied"), ("TOO_MANY_REQUESTS", "throttled"), ("UNKNOWN", "unavailable")],
)
def test_graphql_errors_are_not_empty_success(monkeypatch, code, expected):
    _mock_responses(monkeypatch, {"errors": [{"message": "private-marker", "extensions": {"code": code}}]})
    agents, warnings = runpod.discover(api_key="fixture")
    assert len(agents) == 1
    assert warnings[0].startswith(f"runpod:pods:{expected}:")
    assert "private-marker" not in warnings[0]
    assert "Assessment incomplete" in warnings[0]


@pytest.mark.parametrize(
    "payload", [{}, {"data": {}}, {"data": {"myself": {}}}, {"data": {"myself": {"pods": None}}}, {"data": {"myself": {"pods": "invalid"}}}]
)
def test_missing_collection_is_not_empty_success(monkeypatch, payload):
    _mock_responses(monkeypatch, payload)
    agents, warnings = runpod.discover(api_key="fixture")
    assert len(agents) == 1
    assert len(warnings) == 1
    assert warnings[0].startswith("runpod:pods:unavailable:")


def test_explicit_empty_collections_succeed(monkeypatch):
    _mock_responses(monkeypatch, {"data": {"myself": {"pods": []}}}, {"data": {"myself": {"endpoints": []}}})
    assert runpod.discover(api_key="fixture") == ([], [])


def test_endpoint_failure_keeps_pods(monkeypatch):
    _mock_responses(
        monkeypatch,
        {"data": {"myself": {"pods": [{"id": "pod-one", "name": "fixture"}]}}},
        {"errors": [{"extensions": {"code": "FORBIDDEN"}}]},
    )
    agents, warnings = runpod.discover(api_key="fixture")
    assert [a.name for a in agents] == ["runpod:fixture"]
    assert warnings[0].startswith("runpod:endpoints:denied:")


@pytest.mark.parametrize(
    "errors",
    [
        [{"message": "private-marker"}],
        "private-marker",
        [{"extensions": {"code": []}}],
        [{"extensions": {"code": "FORBIDDEN"}}, {"extensions": {"code": "TOO_MANY_REQUESTS"}}],
    ],
)
def test_unknown_or_mixed_graphql_failures_are_unavailable(monkeypatch, errors):
    _mock_responses(monkeypatch, {"errors": errors, "data": {"myself": {"pods": [{"id": "untrusted-partial"}]}}})
    agents, warnings = runpod.discover(api_key="fixture")
    assert [a.name for a in agents] == ["runpod-serverless:fixture"]
    assert warnings[0].startswith("runpod:pods:unavailable:")
    assert "private-marker" not in warnings[0]


def test_offline_mode_reports_both_stages_incomplete(monkeypatch):
    from agent_bom.http_client import OfflineModeError

    def request(*args, **kwargs):
        raise OfflineModeError("fixture offline")

    monkeypatch.setattr(runpod.http_client, "sync_request_with_retry", request)
    agents, warnings = runpod.discover(api_key="fixture")
    assert agents == []
    assert len(warnings) == 2
    assert warnings[0].startswith("runpod:pods:unavailable:")
    assert warnings[1].startswith("runpod:endpoints:unavailable:")
