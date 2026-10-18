"""Fixed-window native pages never silently truncate or cross project scope."""

import json
from contextlib import contextmanager

import pytest

from agent_bom import trace_connectors as connectors


class Client:
    def __init__(self, *payloads):
        self.payloads = iter(payloads)
        self.calls = []

    @contextmanager
    def stream(self, *args, **kwargs):
        yield self.request(*args, **kwargs)

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        payload = next(self.payloads)
        return type("Response", (), {"status_code": 200, "headers": {}, "iter_bytes": lambda self: iter([json.dumps(payload).encode()])})()


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr(connectors, "_validate_pull_url", lambda _: None)


@pytest.mark.parametrize("status", [429, 503])
@pytest.mark.parametrize("header,expected", [("120", 120), ("999999999", 86400), ("api_key=private-value", 0)])
def test_native_reader_preserves_bounded_retry_timing_without_header_content(status, header, expected):
    import httpx

    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(status, headers={"Retry-After": header}))) as client:
        with pytest.raises(connectors._TraceConnectorHTTPError) as caught:
            connectors._call_json(client, "GET", "https://example.test")
    assert caught.value.retry_after == expected
    assert "private-value" not in str(caught.value)


def test_langfuse_page_uses_fixed_window_cursor_and_preserves_native_kinds():
    client = Client({"data": [{"id": "agent", "name": "root", "type": "AGENT"}], "meta": {"cursor": "second"}})
    page = connectors.fetch_trace_page(
        "langfuse",
        {"host": "https://example.test", "public_key": "pk", "secret_key": "sk"},
        project_id="project",
        window_start="2026-10-11T00:00:00Z",
        window_end="2026-10-12T00:00:00Z",
        cursor="first",
        limit=10,
        client=client,
    )
    assert page.cursor == "second"
    assert page.fetched == 1
    assert page.payload["spans"][0]["spanId"] == "agent"
    params = client.calls[0][2]["params"]
    assert params["cursor"] == "first"
    assert params["fromStartTime"] == "2026-10-11T00:00:00Z"
    assert params["toStartTime"] == "2026-10-12T00:00:00Z"
    assert "type" not in params
    assert "io" not in params["fields"].split(",")
    assert "time" in params["fields"].split(",")


@pytest.mark.parametrize(
    "payload",
    [
        {"data": [], "meta": {"cursor": "same"}},
        {"data": [], "meta": {"cursor": 123}},
        {"data": [], "meta": "broken"},
        {"data": [None], "meta": {"cursor": None}},
        {"data": [{"id": "x", "name": "n"}, {"id": "y", "name": "n"}], "meta": {"cursor": None}},
    ],
)
def test_malformed_or_nonadvancing_page_never_claims_completion(payload):
    with pytest.raises(connectors.TraceConnectorError):
        connectors.fetch_trace_page(
            "langfuse",
            {"host": "https://example.test", "public_key": "pk", "secret_key": "sk"},
            project_id="project",
            window_start="2026-10-11T00:00:00Z",
            window_end="2026-10-12T00:00:00Z",
            cursor="same",
            limit=1,
            client=Client(payload),
        )


def test_project_is_resolved_from_authorized_provider_response():
    client = Client({"data": [{"id": "authorized"}]})
    assert (
        connectors.resolve_trace_project(
            "langfuse", {"host": "https://example.test", "public_key": "pk", "secret_key": "sk"}, client=client
        )
        == "authorized"
    )
    assert client.calls[0][1].endswith("/api/public/projects")


def test_langfuse_operator_project_hint_scopes_a_multi_project_key():
    client = Client({"data": [{"id": "project-a", "name": "staging"}, {"id": "project-b", "name": "production"}]})
    resolved = connectors.resolve_trace_project(
        "langfuse",
        {"host": "https://example.test", "public_key": "pk", "secret_key": "sk", "project": "production"},
        client=client,
    )
    assert resolved == "project-b"


def test_langfuse_page_without_cursor_metadata_is_a_complete_page():
    client = Client({"data": [{"id": "span", "name": "root", "type": "AGENT"}], "meta": {}})
    page = connectors.fetch_trace_page(
        "langfuse",
        {"host": "https://example.test", "public_key": "pk", "secret_key": "sk"},
        project_id="project",
        window_start="2026-10-11T00:00:00Z",
        window_end="2026-10-12T00:00:00Z",
        cursor=None,
        limit=10,
        client=client,
    )
    assert page.fetched == 1
    assert page.cursor is None


def test_langsmith_page_without_cursor_metadata_is_a_complete_page():
    client = Client({"runs": [{"id": "run", "name": "root", "run_type": "chain"}]})
    page = connectors.fetch_trace_page(
        "langsmith",
        {"api_url": "https://example.test", "api_key": "key"},
        project_id="project",
        window_start="2026-10-11T00:00:00Z",
        window_end="2026-10-12T00:00:00Z",
        cursor=None,
        limit=10,
        client=client,
    )
    assert page.fetched == 1
    assert page.cursor is None


def test_langsmith_project_and_native_page_do_not_use_session_as_conversation():
    client = Client({"runs": [{"id": "run", "name": "root", "run_type": "chain", "session_id": "project"}], "cursors": {"next": "more"}})
    page = connectors.fetch_trace_page(
        "langsmith",
        {"api_url": "https://example.test", "api_key": "key"},
        project_id="project",
        window_start="2026-10-11T00:00:00Z",
        window_end="2026-10-12T00:00:00Z",
        cursor=None,
        limit=1000,
        client=client,
    )
    assert page.cursor == "more"
    body = client.calls[0][2]["json"]
    assert body["session"] == ["project"]
    assert body["limit"] == 100
    assert "inputs" not in body["select"] and "outputs" not in body["select"]
    assert "start_time" in body["filter"]
    attrs = {item["key"]: item["value"]["stringValue"] for item in page.payload["spans"][0]["attributes"]}
    assert attrs["agent_bom.native_project_id"] == "project"
    assert "agent_bom.native_session_id" not in attrs
