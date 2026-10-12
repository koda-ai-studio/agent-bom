"""Native Langfuse / LangSmith trace-pull connectors (#3899).

Pulled traces must feed the same ``otel_ingest`` parser and per-span correlation
as pushed OTLP. HTTP is mocked; credentials are used for auth only.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom import security as _security
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, MCPTool, Package, Severity, Vulnerability
from agent_bom.otel_ingest import parse_otel_traces
from agent_bom.runtime_correlation import correlate_spans_to_attack_paths
from agent_bom.trace_connectors import (
    TraceConnectorError,
    TraceConnectorValidationError,
    fetch_langfuse_traces,
    fetch_langsmith_traces,
    fetch_traces,
    list_trace_connectors,
)

# Real SSRF guard, captured before the autouse stub replaces it. The mapping
# tests below use placeholder hosts that don't resolve, so the network-dependent
# URL validation is stubbed for them; the dedicated SSRF tests restore the real
# guard to prove unsafe hosts are rejected before any request.
_REAL_VALIDATE_URL = _security.validate_url


@pytest.fixture(autouse=True)
def _stub_url_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """No-op the URL guard so placeholder-host mapping tests stay hermetic."""
    monkeypatch.setattr("agent_bom.security.validate_url", lambda *a, **k: None)


class _FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Records the last request and returns a canned payload."""

    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        return _FakeResponse(self.payload, self.status_code)


def _blast_radius() -> BlastRadius:
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2025-7777", summary="x", severity=Severity.HIGH, is_kev=False),
        package=Package(name="requests", version="2.0.0", ecosystem="pypi"),
        affected_servers=[MCPServer(name="shell-mcp")],
        affected_agents=[Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp")],
        exposed_credentials=["AWS_SECRET_ACCESS_KEY"],
        exposed_tools=[MCPTool(name="run_shell", description="d")],
    )
    br.calculate_risk_score()
    return br


def test_list_trace_connectors_advertises_langfuse_and_langsmith() -> None:
    names = {c["name"] for c in list_trace_connectors()}
    assert {"langfuse", "langsmith"} <= names


def test_langfuse_pull_maps_to_otlp_and_uses_basic_auth() -> None:
    client = _FakeClient({"data": [{"id": "obs-1", "traceId": "tr-1", "name": "run_shell", "metadata": {"server": "shell-mcp"}}]})
    otlp = fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", client=client)
    # Credentials are passed for auth only.
    assert client.calls[0]["auth"] == ("pk", "sk")
    traces = parse_otel_traces(otlp)
    assert traces[0].tool_name == "run_shell"
    assert traces[0].server_name == "shell-mcp"
    assert traces[0].span_id == "obs-1"


def test_langsmith_pull_maps_to_otlp_and_uses_api_key_header() -> None:
    client = _FakeClient(
        {"runs": [{"id": "run-1", "trace_id": "tr-9", "name": "run_shell", "extra": {"metadata": {"server": "shell-mcp"}}}]}
    )
    otlp = fetch_langsmith_traces(api_key="ls-key", client=client)
    assert client.calls[0]["headers"]["x-api-key"] == "ls-key"
    traces = parse_otel_traces(otlp)
    assert traces[0].tool_name == "run_shell"
    assert traces[0].span_id == "run-1"


def test_pulled_traces_feed_span_correlation() -> None:
    client = _FakeClient({"data": [{"id": "obs-1", "traceId": "tr-1", "name": "run_shell", "metadata": {"server": "shell-mcp"}}]})
    otlp = fetch_traces("langfuse", {"host": "https://c", "public_key": "pk", "secret_key": "sk"}, client=client)
    traces = parse_otel_traces(otlp)
    paths = correlate_spans_to_attack_paths(traces, [_blast_radius()])
    assert len(paths) == 1
    assert paths[0].vulnerability_id == "CVE-2025-7777"
    assert paths[0].span_id == "obs-1"


def test_langfuse_content_only_included_when_opted_in() -> None:
    payload = {"data": [{"id": "o", "traceId": "t", "name": "read_file", "output": "secret AKIAIOSFODNN7EXAMPLE"}]}
    without = fetch_langfuse_traces(host="https://c", public_key="pk", secret_key="sk", client=_FakeClient(payload))
    assert "AKIAIOSFODNN7EXAMPLE" not in repr(without)
    with_content = fetch_langfuse_traces(
        host="https://c", public_key="pk", secret_key="sk", include_content=True, client=_FakeClient(payload)
    )
    assert "AKIAIOSFODNN7EXAMPLE" in repr(with_content)


def test_missing_credentials_and_http_error_raise() -> None:
    with pytest.raises(TraceConnectorError):
        fetch_langfuse_traces(host="https://c", public_key="", secret_key="sk")
    with pytest.raises(TraceConnectorError):
        fetch_langsmith_traces(api_key="k", client=_FakeClient({}, status_code=401))
    with pytest.raises(TraceConnectorError):
        fetch_traces("unknown-provider", {"api_key": "k"})


# ─── SSRF hardening ──────────────────────────────────────────────────────────
# The connector host is caller-supplied; without a guard a runtime_ingest caller
# could make the control plane fetch internal services or cloud metadata (SSRF).
# These tests restore the real ``validate_url`` guard. Every rejected host is
# refused on scheme (non-HTTPS) or IP-literal grounds — i.e. before any DNS
# lookup — so they run offline with no network.

_SSRF_HOSTS = [
    "http://169.254.169.254/latest/meta-data",  # cloud metadata (link-local)
    "http://localhost",  # loopback
    "http://10.0.0.1",  # private RFC1918
    "http://",  # malformed / no host
    "https://10.0.0.1",  # private even over https
]


@pytest.mark.parametrize("host", _SSRF_HOSTS)
def test_langfuse_rejects_unsafe_host_before_any_request(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    monkeypatch.setattr("agent_bom.security.validate_url", _REAL_VALIDATE_URL)
    client = _FakeClient({"data": []})
    with pytest.raises(TraceConnectorValidationError) as excinfo:
        fetch_langfuse_traces(host=host, public_key="pk", secret_key="sk", client=client)
    # Rejected before the HTTP client was ever touched (no network / port scan).
    assert client.calls == []
    # The rejection is a bad-request-shaped error and never echoes the raw URL.
    assert isinstance(excinfo.value, TraceConnectorError)
    message = str(excinfo.value)
    assert host not in message
    assert "169.254" not in message and "10.0.0.1" not in message and "localhost" not in message


@pytest.mark.parametrize("api_url", _SSRF_HOSTS)
def test_langsmith_rejects_unsafe_api_url_before_any_request(monkeypatch: pytest.MonkeyPatch, api_url: str) -> None:
    monkeypatch.setattr("agent_bom.security.validate_url", _REAL_VALIDATE_URL)
    client = _FakeClient({"runs": []})
    with pytest.raises(TraceConnectorValidationError) as excinfo:
        fetch_langsmith_traces(api_key="ls-key", api_url=api_url, client=client)
    assert client.calls == []
    message = str(excinfo.value)
    assert api_url not in message
    assert "169.254" not in message and "10.0.0.1" not in message


def test_valid_public_https_host_passes_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    # A public IPv4 literal validates offline (numeric resolution, no DNS) and
    # lets the (mocked) fetch proceed — behavior is unchanged for safe hosts.
    monkeypatch.setattr("agent_bom.security.validate_url", _REAL_VALIDATE_URL)
    client = _FakeClient({"data": [{"id": "o", "traceId": "t", "name": "run_shell"}]})
    otlp = fetch_langfuse_traces(host="https://93.184.216.34", public_key="pk", secret_key="sk", client=client)
    assert client.calls, "valid public host must proceed to the HTTP fetch"
    assert parse_otel_traces(otlp)[0].tool_name == "run_shell"


@pytest.mark.parametrize("provider,key", [("langfuse", "data"), ("langsmith", "runs")])
@pytest.mark.parametrize("records", [None, {}, "not-a-list", [{"id": "broken"}]])
def test_invalid_provider_records_are_not_a_successful_empty_pull(provider, key, records):
    credentials = {"host": "https://cloud.example", "public_key": "pk", "secret_key": "sk", "api_key": "key"}
    with pytest.raises(TraceConnectorError, match="invalid"):
        fetch_traces(provider, credentials, client=_FakeClient({key: records}))


def test_langfuse_does_not_turn_generations_into_tool_calls():
    client = _FakeClient(
        {
            "data": [
                {"id": "llm", "traceId": "t", "name": "read_file", "type": "GENERATION", "model": "gpt-test"},
                {"id": "tool", "traceId": "t", "name": "read_file", "type": "TOOL"},
            ]
        }
    )
    traces = parse_otel_traces(fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", client=client))
    assert [span.span_id for span in traces] == ["tool"]


def test_langsmith_project_scope_resolves_name_before_query():
    class ProjectClient(_FakeClient):
        def request(self, method, url, **kwargs):
            self.calls.append({"method": method, "url": url, **kwargs})
            return _FakeResponse([{"id": "project-123", "name": "production"}] if method == "GET" else {"runs": []})

    client = ProjectClient(None)
    fetch_langsmith_traces(api_key="key", project="production", client=client)
    assert client.calls[0]["url"].endswith("/sessions")
    assert client.calls[0]["params"]["name"] == "production"
    assert client.calls[1]["json"]["session"] == ["project-123"]
    assert "project_name" not in client.calls[1]["json"]


def test_langsmith_missing_project_never_falls_back_to_all_projects():
    client = _FakeClient([])
    with pytest.raises(TraceConnectorError):
        fetch_langsmith_traces(api_key="key", project="missing", client=client)
    assert len(client.calls) == 1
    assert client.calls[0]["method"] == "GET"


def test_langsmith_project_session_is_not_a_trace_id():
    client = _FakeClient({"runs": [{"id": "r", "name": "read_file", "session_id": "project-id"}]})
    assert parse_otel_traces(fetch_langsmith_traces(api_key="key", client=client))[0].trace_id == ""


def test_provider_cannot_expand_requested_sample():
    client = _FakeClient({"data": [{"id": str(i), "name": "read_file", "type": "TOOL"} for i in range(5)]})
    payload = fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", limit=2, client=client)
    assert len(payload["spans"]) == 2


def test_invalid_json_is_a_safe_connector_error():
    class InvalidJsonClient:
        def request(self, *args, **kwargs):
            class InvalidJsonResponse:
                status_code = 200

                def json(self):
                    raise ValueError("private-upstream-response")

            return InvalidJsonResponse()

    with pytest.raises(TraceConnectorError) as caught:
        fetch_langsmith_traces(api_key="key", client=InvalidJsonClient())
    assert "invalid JSON" in str(caught.value)
    assert "private-upstream-response" not in str(caught.value)


@pytest.mark.parametrize("include_content", [False, True])
def test_langfuse_v2_requests_bounded_native_metadata_without_unconsented_io(include_content):
    from datetime import datetime, timedelta

    client = _FakeClient({"data": []})
    fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", include_content=include_content, client=client)
    call = client.calls[0]
    assert call["url"].endswith("/api/public/v2/observations")
    params = call["params"]
    assert "type" not in params
    assert set(params["fields"].split(",")) == {"core", "basic", "metadata"} | ({"io"} if include_content else set())
    assert datetime.fromisoformat(params["toStartTime"]) - datetime.fromisoformat(params["fromStartTime"]) == timedelta(days=1)


def test_langfuse_v3_fallback_only_when_v2_route_is_missing():
    class LegacyClient(_FakeClient):
        def request(self, method, url, **kwargs):
            super().request(method, url, **kwargs)
            if "/v2/" in url:
                return _FakeResponse({}, 404)
            return _FakeResponse({"data": [{"id": "legacy", "name": "read_file"}]})

    client = LegacyClient({})
    result = fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", client=client)
    assert len(result["spans"]) == 1
    assert len(client.calls) == 2
    assert client.calls[1]["url"].endswith("/api/public/observations")


@pytest.mark.parametrize("status", [401, 403, 410, 429, 500])
def test_langfuse_v2_errors_do_not_downgrade_or_retry(status):
    client = _FakeClient({}, status_code=status)
    with pytest.raises(TraceConnectorError, match=f"HTTP {status}"):
        fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", client=client)
    assert len(client.calls) == 1
