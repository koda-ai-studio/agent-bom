"""Tests for CI deployment health probe helpers."""

from __future__ import annotations

import urllib.error

import pytest

from agent_bom.deployment_probe import (
    fetch_health,
    main,
    resolve_health_url,
    resolve_server_card_url,
    validate_health_payload,
    validate_server_card_release,
)


@pytest.mark.parametrize(
    "initial_payload",
    [
        b'{"serverInfo":{"version":"0.103.2"},"tools":[]}',
        b'{"serverInfo":{"version":"0.104.0"},"tools":[]}',
        b'{"serverInfo":{"version":"0.104.0"},"tools":[{"name":"scan"}]}',
    ],
)
def test_server_card_cli_retries_until_exact_release_contract(monkeypatch, capsys, initial_payload):
    replies = iter([initial_payload, b'{"serverInfo":{"version":"0.104.0"},"tools":[{"name":"scan","inputSchema":{"type":"object"}}]}'])
    delays = []
    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", lambda *_args, **_kwargs: _Response(next(replies)))
    monkeypatch.setattr("agent_bom.deployment_probe.time.sleep", delays.append)

    assert (
        main(["--server-card", "--expected-version", "0.104.0", "--expected-tool-count", "1", "--attempts", "2", "--backoff-seconds", "3"])
        == 0
    )
    captured = capsys.readouterr()
    assert '"version":"0.104.0"' in captured.out
    assert delays == [3]


def test_server_card_cli_still_fails_when_release_never_arrives(monkeypatch, capsys):
    calls = []

    def old_release(*_args, **_kwargs):
        calls.append(True)
        return _Response(b'{"serverInfo":{"version":"0.103.2"},"tools":[]}')

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", old_release)

    assert (
        main(["--server-card", "--expected-version", "0.104.0", "--expected-tool-count", "1", "--attempts", "3", "--backoff-seconds", "0"])
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "version mismatch" in captured.err
    assert len(calls) == 3


def test_server_card_network_and_contract_errors_share_attempt_budget(monkeypatch, capsys):
    calls = []

    def changing_failure(*_args, **_kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise urllib.error.URLError("temporarily unavailable")
        return _Response(b'{"serverInfo":{"version":"0.103.2"},"tools":[]}')

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", changing_failure)

    assert main(["--server-card", "--expected-version", "0.104.0", "--expected-tool-count", "1", "--attempts", "2"]) == 1
    assert len(calls) == 2
    assert "version mismatch" in capsys.readouterr().err


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def test_resolve_health_url_accepts_root_base_url():
    assert resolve_health_url("https://agent-bom-mcp.up.railway.app") == "https://agent-bom-mcp.up.railway.app/health"
    assert resolve_health_url("https://agent-bom-mcp.up.railway.app/") == "https://agent-bom-mcp.up.railway.app/health"


def test_resolve_health_url_strips_mcp_suffix():
    assert resolve_health_url("https://agent-bom-mcp.up.railway.app/mcp") == "https://agent-bom-mcp.up.railway.app/health"
    assert resolve_health_url("https://agent-bom-mcp.up.railway.app/nested/mcp") == "https://agent-bom-mcp.up.railway.app/nested/health"


def test_resolve_server_card_url_uses_public_well_known_route():
    expected = "https://agent-bom-mcp.up.railway.app/.well-known/mcp/server-card.json"
    assert resolve_server_card_url("https://agent-bom-mcp.up.railway.app") == expected
    assert resolve_server_card_url("https://agent-bom-mcp.up.railway.app/mcp") == expected


def test_fetch_health_retries_normalized_url(monkeypatch):
    calls: list[str] = []

    def fake_urlopen(request, timeout):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.URLError("temporary failure")
        assert timeout == 12
        return _Response(b'{"version":"0.76.0","tool_count":0}')

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("agent_bom.deployment_probe.time.sleep", lambda *_args: None)

    url, payload = fetch_health(
        "https://agent-bom-mcp.up.railway.app/mcp",
        bearer_token="secret",
        attempts=2,
        backoff_seconds=5,
        timeout=12,
    )

    assert url == "https://agent-bom-mcp.up.railway.app/health"
    assert payload["version"] == "0.76.0"
    assert calls == [
        "https://agent-bom-mcp.up.railway.app/health",
        "https://agent-bom-mcp.up.railway.app/health",
    ]


def test_validate_health_payload_rejects_auth_required_for_public_registry():
    with pytest.raises(ValueError, match="requires auth"):
        validate_health_payload({"version": "0.76.0", "auth_required": True}, forbid_auth_required=True)


def test_validate_health_payload_allows_public_surface():
    payload = validate_health_payload({"version": "0.76.0", "auth_required": False}, forbid_auth_required=True)
    assert payload["version"] == "0.76.0"


def test_validate_server_card_release_requires_exact_version_tools_and_schemas():
    payload = {
        "serverInfo": {"version": "0.100.0"},
        "tools": [
            {"name": "scan", "inputSchema": {"type": "object"}},
            {"name": "generate_sbom", "inputSchema": {"type": "object"}},
        ],
    }

    validated = validate_server_card_release(payload, expected_version="0.100.0", expected_tool_count=2)
    assert validated is payload

    with pytest.raises(ValueError, match="version mismatch"):
        validate_server_card_release(payload, expected_version="0.101.0", expected_tool_count=2)
    with pytest.raises(ValueError, match="tool count mismatch"):
        validate_server_card_release(payload, expected_version="0.100.0", expected_tool_count=3)

    payload["tools"][1].pop("inputSchema")
    with pytest.raises(ValueError, match="tool schema"):
        validate_server_card_release(payload, expected_version="0.100.0", expected_tool_count=2)


_FULL = ["check", "compliance", "exposure_paths", "generate_sbom", "intel_lookup", "policy_check", "remediate", "scan"]
_READ_ONLY = [name for name in _FULL if name != "scan"]


def _card(names, *, scheme, read_only_hint=True):
    tools = [
        {"name": name, "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": read_only_hint and name != "scan"}}
        for name in names
    ]
    return {
        "serverInfo": {"version": "0.114.0"},
        "tools": tools,
        "capabilities": {"read_only": all(tool["annotations"]["readOnlyHint"] for tool in tools)},
        "authentication": {"required": True, "schemes": [scheme]},
    }


def _validate(card, **kwargs):
    return validate_server_card_release(
        card, expected_version="0.114.0", expected_tool_names=_FULL, expected_read_only_tool_names=_READ_ONLY, **kwargs
    )


def test_oauth_card_is_held_to_the_read_only_registered_set():
    """The v0.114.0 hosted card (OAuth, 7 read-only tools) is the exact contract."""
    assert _validate(_card(_READ_ONLY, scheme="oauth2"), expected_auth_scheme="oauth2")
    with pytest.raises(ValueError, match="tool set mismatch"):
        _validate(_card(_FULL, scheme="oauth2"), expected_auth_scheme="oauth2")


def test_bearer_card_is_held_to_the_full_default_profile():
    assert _validate(_card(_FULL, scheme="bearer"), expected_auth_scheme="bearer")
    with pytest.raises(ValueError, match="tool set mismatch"):
        _validate(_card(_READ_ONLY, scheme="bearer"), expected_auth_scheme="bearer")


def test_oauth_card_exposing_a_write_tool_fails_closed():
    card = _card(_READ_ONLY, scheme="oauth2")
    card["tools"][0]["annotations"]["readOnlyHint"] = False
    with pytest.raises(ValueError, match="non-read-only"):
        _validate(card, expected_auth_scheme="oauth2")
    extra = _card([*_READ_ONLY, "graph_correlate"], scheme="oauth2")
    with pytest.raises(ValueError, match="tool set mismatch.*graph_correlate"):
        _validate(extra, expected_auth_scheme="oauth2")
    renamed = _card([*_READ_ONLY[:-1], "endpoint_sync"], scheme="oauth2")
    with pytest.raises(ValueError, match="tool set mismatch"):
        _validate(renamed, expected_auth_scheme="oauth2")


def test_card_must_declare_the_auth_scheme_the_probe_used():
    with pytest.raises(ValueError, match="authentication scheme mismatch"):
        _validate(_card(_FULL, scheme="bearer"), expected_auth_scheme="oauth2")
    with pytest.raises(ValueError, match="authentication scheme mismatch"):
        _validate(_card(_READ_ONLY, scheme="oauth2"), expected_auth_scheme="bearer")


def test_oauth_card_without_a_read_only_expectation_fails_closed():
    with pytest.raises(ValueError, match="read-only"):
        validate_server_card_release(_card(_READ_ONLY, scheme="oauth2"), expected_version="0.114.0", expected_tool_names=_FULL)


def test_server_card_cli_selects_the_read_only_names_for_an_oauth_card(monkeypatch, capsys, tmp_path):
    import json

    full, read_only = tmp_path / "full.json", tmp_path / "read-only.json"
    full.write_text(json.dumps(_FULL))
    read_only.write_text(json.dumps(_READ_ONLY))
    body = json.dumps(_card(_READ_ONLY, scheme="oauth2")).encode()
    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", lambda *_a, **_k: _Response(body))
    arguments = ["--server-card", "--expected-version", "0.114.0", "--expected-tool-names-file", str(full)]
    arguments += ["--expected-read-only-tool-names-file", str(read_only), "--expected-auth-scheme", "oauth2"]
    assert main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["serverInfo"]["version"] == "0.114.0"
    assert main([*arguments[:-1], "bearer"]) == 1
    assert "authentication scheme mismatch" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main([*arguments, "--expected-tool-count", "8"])


@pytest.mark.parametrize("sse", [False, True])
@pytest.mark.parametrize("anonymous_status", [401, 403])
def test_authenticated_initialize_accepts_json_and_event_stream(monkeypatch, sse, anonymous_status):
    import io
    import json
    from email.message import Message
    from types import SimpleNamespace

    from agent_bom.deployment_probe import verify_mcp_auth

    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "serverInfo": {"version": "0.105.0"},
            },
        }
    )
    response = io.BytesIO((f"event: message\ndata: {payload}\n\n" if sse else payload).encode())
    response.headers = Message()
    response.headers["Content-Type"] = "text/event-stream" if sse else "application/json"
    calls = []

    def open_request(request, **kwargs):
        calls.append(request)
        if not request.get_header("Authorization"):
            raise urllib.error.HTTPError(request.full_url, anonymous_status, "fixture", {}, None)
        return response

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=open_request))
    verify_mcp_auth("https://example.com/mcp", bearer_token="fixture-read-token", expected_version="0.105.0", timeout=1)
    assert calls[0].full_url == "https://example.com/mcp"
    assert calls[0].get_method() == "POST"
    assert calls[0].get_header("Authorization") == "Bearer fixture-read-token"
    assert json.loads(calls[0].data)["method"] == "initialize"
    assert len(calls) == 2
    assert calls[1].get_header("Authorization") is None


def test_expired_authenticated_access_cannot_pass_public_card_gate(monkeypatch, capsys):
    from types import SimpleNamespace

    def denied(*args, **kwargs):
        raise urllib.error.HTTPError("https://secret.example/credential", 401, "token=private-token", {}, None)

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=denied))
    monkeypatch.setattr(
        "agent_bom.deployment_probe.fetch_server_card", lambda *args, **kwargs: pytest.fail("public metadata cannot override auth failure")
    )
    result = main(
        [
            "--server-card",
            "--require-mcp-auth",
            "--bearer-token",
            "private-token",
            "--expected-version",
            "0.105.0",
            "--expected-tool-count",
            "8",
        ]
    )
    assert result == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Authenticated MCP initialize failed (HTTP 401)" in captured.err
    assert "private-token" not in captured.err
    assert "secret.example" not in captured.err
    assert "token=private-token" not in captured.err


def test_unreachable_mcp_origin_names_the_failure_kind_without_the_host(monkeypatch, capsys):
    from types import SimpleNamespace

    def unreachable(*args, **kwargs):
        raise urllib.error.URLError(ConnectionRefusedError(61, "secret.example refused"))

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=unreachable))
    result = main(["--require-mcp-auth", "--bearer-token", "private-token", "--attempts", "1", "--backoff-seconds", "0"])
    assert result == 1
    err = capsys.readouterr().err
    assert "Authenticated MCP initialize failed (connection error: ConnectionRefusedError)" in err
    assert "secret.example" not in err


@pytest.mark.parametrize("becomes_ready", [True, False])
def test_authenticated_probe_retries_readiness_but_fails_closed(monkeypatch, capsys, becomes_ready):
    calls = []
    delays = []

    def initialize(*args, **kwargs):
        calls.append(kwargs)
        if not becomes_ready or len(calls) < 2:
            raise RuntimeError("Authenticated MCP initialize failed; check credential validity and deployed release")

    def public_card(*args, **kwargs):
        assert becomes_ready, "public metadata must not override failed authentication"
        return "https://example.com/.well-known/mcp/server-card.json", {"version": "0.110.0"}

    monkeypatch.setattr("agent_bom.deployment_probe.verify_mcp_auth", initialize)
    monkeypatch.setattr("agent_bom.deployment_probe.fetch_server_card", public_card)
    monkeypatch.setattr("agent_bom.deployment_probe.time.sleep", delays.append)
    result = main(
        [
            "--server-card",
            "--require-mcp-auth",
            "--bearer-token",
            "fixture-token",
            "--expected-version",
            "0.110.0",
            "--expected-tool-count",
            "8",
            "--attempts",
            "3",
            "--backoff-seconds",
            "2",
        ]
    )
    assert result == (0 if becomes_ready else 1)
    assert len(calls) == (2 if becomes_ready else 3)
    assert delays == ([2] if becomes_ready else [2, 4])
    captured = capsys.readouterr()
    assert "fixture-token" not in captured.out + captured.err
    if not becomes_ready:
        assert captured.out == ""


def test_authenticated_probe_requires_credential_and_safe_origin(monkeypatch):
    from agent_bom.deployment_probe import verify_mcp_auth

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: pytest.fail("must reject before network"))
    for url, token in [
        ("https://example.com", None),
        ("http://example.com", "read-token"),
        ("https://user:password@example.com", "read-token"),
    ]:
        with pytest.raises(ValueError):
            verify_mcp_auth(url, bearer_token=token, expected_version="0.105.0", timeout=1)


def test_authenticated_probe_does_not_forward_bearer_on_redirect():
    from agent_bom.deployment_probe import _NoAuthRedirect

    with pytest.raises(ValueError, match="does not follow redirects"):
        _NoAuthRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.example/mcp")


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "2.0", "id": 1, "error": {"message": "credential=private-response"}},
        {"jsonrpc": "2.0", "id": 2, "result": {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"version": "0.105.0"}}},
        {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"version": "0.104.0"}}},
        [],
    ],
)
def test_authenticated_probe_rejects_invalid_success_bodies_without_leaking(monkeypatch, capsys, payload):
    import io
    import json
    from email.message import Message
    from types import SimpleNamespace

    response = io.BytesIO(json.dumps(payload).encode())
    response.headers = Message()
    response.headers["Content-Type"] = "application/json"
    monkeypatch.setattr(
        "agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=lambda *a, **k: response)
    )
    assert main(["--require-mcp-auth", "--bearer-token", "fixture-token", "--expected-version", "0.105.0"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-response" not in captured.err
    assert "Authenticated MCP initialize failed" in captured.err


@pytest.mark.parametrize("anonymous_status", [200, 404, 500])
def test_authenticated_probe_rejects_unprotected_or_unverifiable_endpoint(monkeypatch, anonymous_status):
    import io
    import json
    from email.message import Message
    from types import SimpleNamespace

    from agent_bom.deployment_probe import verify_mcp_auth

    calls = []

    def open_request(request, **kwargs):
        calls.append(request)
        if not request.get_header("Authorization") and anonymous_status != 200:
            raise urllib.error.HTTPError(request.full_url, anonymous_status, "fixture", {}, None)
        response = io.BytesIO(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "serverInfo": {"version": "0.105.0"},
                    },
                }
            ).encode()
        )
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        return response

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=open_request))
    with pytest.raises(RuntimeError, match="Authenticated MCP initialize failed"):
        verify_mcp_auth("https://example.com", bearer_token="fixture-token", expected_version="0.105.0", timeout=1)
    assert len(calls) == 2
    assert calls[1].get_header("Authorization") is None


# ── Public read-only tier probe (exercised against the real server app) ────


class _TestClientOpener:
    """Route urllib requests from the probe into an in-process MCP app."""

    def __init__(self, client):
        self.client = client
        self.requests = []

    def open(self, request, timeout=None):
        import io
        import urllib.parse
        from email.message import Message

        self.requests.append(request)
        path = urllib.parse.urlsplit(request.full_url).path
        response = self.client.post(path, content=request.data, headers=dict(request.header_items()))
        if response.status_code >= 400:
            raise urllib.error.HTTPError(request.full_url, response.status_code, "fixture", Message(), None)
        body = io.BytesIO(response.content)
        body.headers = Message()
        for key, value in response.headers.items():
            body.headers[key] = value
        return body


def _public_tier_client(monkeypatch, tmp_path, *, public=True):
    from datetime import datetime, timedelta, timezone

    from starlette.testclient import TestClient

    from agent_bom.mcp_server import create_mcp_server

    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="fixture-read-token", profile="scan", public_readonly=public)
    return TestClient(server.streamable_http_app(), base_url="http://localhost:8000")


def _route_probe(monkeypatch, client):
    from types import SimpleNamespace

    opener = _TestClientOpener(client)
    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=opener.open))
    return opener


def test_public_readonly_probe_passes_against_the_public_tier(monkeypatch, tmp_path):
    from agent_bom import __version__
    from agent_bom.deployment_probe import verify_public_readonly

    with _public_tier_client(monkeypatch, tmp_path) as client:
        opener = _route_probe(monkeypatch, client)
        names = verify_public_readonly("https://example.com", expected_version=__version__, timeout=1)
        assert names == ["check", "intel_lookup"]
        assert all(request.get_header("Authorization") is None for request in opener.requests)


def test_public_readonly_probe_fails_against_a_bearer_only_server(monkeypatch, tmp_path):
    from agent_bom import __version__
    from agent_bom.deployment_probe import verify_public_readonly

    with _public_tier_client(monkeypatch, tmp_path, public=False) as client:
        _route_probe(monkeypatch, client)
        with pytest.raises(RuntimeError, match="HTTP 401"):
            verify_public_readonly("https://example.com", expected_version=__version__, timeout=1)


def test_public_readonly_probe_fails_when_every_tool_is_anonymous(monkeypatch, tmp_path):
    """A server that answers a non-allowlisted anonymous call is not the public tier."""
    from agent_bom import __version__
    from agent_bom.deployment_probe import verify_public_readonly

    monkeypatch.setattr("agent_bom.mcp_tools.public_tier.anonymous_call_allowed", lambda name: True)
    with _public_tier_client(monkeypatch, tmp_path) as client:
        _route_probe(monkeypatch, client)
        with pytest.raises(RuntimeError, match="must (list only the public lookup tools|be rejected)"):
            verify_public_readonly("https://example.com", expected_version=__version__, timeout=1)


def test_public_readonly_card_must_match_the_anonymous_catalog():
    from agent_bom.deployment_probe import validate_public_readonly_card

    card = {"authentication": {"required": True, "public_readonly": True, "anonymous_tools": ["check", "intel_lookup"]}}
    validate_public_readonly_card(card, ["check", "intel_lookup"])
    with pytest.raises(ValueError, match="anonymous"):
        validate_public_readonly_card(card, ["check"])
    with pytest.raises(ValueError, match="public read-only"):
        validate_public_readonly_card({"authentication": {"required": True}}, ["check"])


def test_public_probe_rejects_insecure_origins(monkeypatch):
    from agent_bom.deployment_probe import verify_public_readonly

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: pytest.fail("must reject before network"))
    for url in ("http://example.com/mcp", "https://user:pw@example.com/mcp"):
        with pytest.raises(ValueError):
            verify_public_readonly(url, expected_version="0.1.0", timeout=1)


def test_railway_workflows_probe_configured_authentication():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    deploy = (root / ".github/workflows/deploy-mcp-sse.yml").read_text()
    freshness = (root / ".github/workflows/deployment-freshness.yml").read_text()
    railway = freshness.split("- name: Check Railway deployment", 1)[1].split("- name: Check Smithery", 1)[0]
    for text in (deploy, railway):
        assert "--server-card --require-mcp-auth" in text
        assert "MCP_PROBE_OAUTH_CLIENT_SECRET" in text
        assert "scripts/deploy/probe_with_oauth.py --" in text
    assert railway.index("--require-mcp-auth") < railway.index('echo "probe_failed=false"')


def test_public_readonly_probe_requires_http_401_not_a_jsonrpc_error(monkeypatch, tmp_path):
    from agent_bom import __version__
    from agent_bom.deployment_probe import verify_public_readonly

    monkeypatch.setattr("agent_bom.mcp_tools.public_tier._anonymous_calls_allowed", lambda body: True)
    with _public_tier_client(monkeypatch, tmp_path) as client:
        _route_probe(monkeypatch, client)
        with pytest.raises(RuntimeError, match="must be rejected"):
            verify_public_readonly("https://example.com", expected_version=__version__, timeout=1)
