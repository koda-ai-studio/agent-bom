"""Probe credentials are freshly issued, bounded and never sent to redirects."""

import importlib.util
import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock

import pytest

spec = importlib.util.spec_from_file_location("probe_with_oauth", Path(__file__).parents[1] / "scripts/deploy/probe_with_oauth.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@pytest.fixture
def environment():
    return {
        "MCP_PROBE_OAUTH_" + k: v
        for k, v in dict(
            ISSUER="https://id.example/realms/mcp",
            TOKEN_URL="https://id.example/realms/mcp/token",
            CLIENT_ID="probe",
            CLIENT_SECRET="private-test-value",
            AUDIENCE="https://mcp.example/mcp",
        ).items()
    }


def test_fresh_token_replaces_static_credential_without_inheriting_client_secret(monkeypatch, environment):
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(
        dict(access_token="fresh-token", token_type="Bearer", expires_in=300)
    ).encode()
    monkeypatch.setattr(probe.urllib.request, "build_opener", lambda *handlers: opener)
    environment["RAILWAY_MCP_BEARER_TOKEN"] = "stale-token"
    result = probe.probe_environment(environment)
    assert result["AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"] == "fresh-token"
    assert "MCP_PROBE_OAUTH_CLIENT_SECRET" not in result
    request = opener.open.call_args.args[0]
    assert request.full_url == environment["MCP_PROBE_OAUTH_TOKEN_URL"]
    assert b"grant_type=client_credentials" in request.data
    assert b"scope=read" in request.data


@pytest.mark.parametrize(
    "change", [{"CLIENT_SECRET": ""}, {"TOKEN_URL": "https://other.example/token"}, {"TOKEN_URL": "http://id.example/token"}]
)
def test_bad_configuration_never_requests_a_token(monkeypatch, environment, change):
    opener = MagicMock()
    monkeypatch.setattr(probe.urllib.request, "build_opener", opener)
    environment.update({"MCP_PROBE_OAUTH_" + k: v for k, v in change.items()})
    with pytest.raises(ValueError):
        probe.probe_environment(environment)
    opener.assert_not_called()


@pytest.mark.parametrize("reply", [{"expires_in": 7200}, {"expires_in": True}, {"access_token": "bad\ntoken"}, {"token_type": "other"}])
def test_bad_token_response_fails_closed(monkeypatch, environment, reply):
    opener = MagicMock()
    body = dict(access_token="fresh-token", token_type="Bearer", expires_in=300)
    body.update(reply)
    opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(body).encode()
    monkeypatch.setattr(probe.urllib.request, "build_opener", lambda *handlers: opener)
    with pytest.raises(ValueError):
        probe.probe_environment(environment)


def test_redirect_rejected():
    with pytest.raises(ValueError):
        probe.NoRedirect().redirect_request(None, None, 302, None, None, "https://other.example")


def test_static_mode_preserved():
    assert probe.probe_environment({"RAILWAY_MCP_BEARER_TOKEN": "existing"})["AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"] == "existing"


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://id.example/realms/mcp/token", code, "status text from server", {}, None)


@pytest.mark.parametrize(
    ("exc", "outcome", "detail"),
    [
        (_http_error(503), probe.OUTCOME_AUTH_PROVIDER_UNAVAILABLE, "OAuth token endpoint returned HTTP 503"),
        (_http_error(502), probe.OUTCOME_AUTH_PROVIDER_UNAVAILABLE, "OAuth token endpoint returned HTTP 502"),
        (
            urllib.error.URLError(ConnectionRefusedError(61, "refused")),
            probe.OUTCOME_AUTH_PROVIDER_UNAVAILABLE,
            "unreachable (ConnectionRefusedError)",
        ),
        (TimeoutError("timed out"), probe.OUTCOME_AUTH_PROVIDER_UNAVAILABLE, "timed out"),
        (_http_error(401), probe.OUTCOME_CREDENTIAL_REJECTED, "OAuth token endpoint returned HTTP 401"),
        (_http_error(400), probe.OUTCOME_CREDENTIAL_REJECTED, "OAuth token endpoint returned HTTP 400"),
        (ValueError("Incomplete OAuth probe configuration"), probe.OUTCOME_PROBE_CONFIGURATION, "Incomplete OAuth probe configuration"),
    ],
)
def test_token_failures_are_classified_without_leaking_the_response(exc, outcome, detail):
    got_outcome, got_detail = probe.classify_token_failure(exc)
    assert got_outcome == outcome
    assert detail in got_detail
    # The HTTP reason phrase is server-controlled text and the URL names the issuer; neither is printed.
    assert "status text from server" not in got_detail
    assert "id.example" not in got_detail


def test_main_reports_the_token_endpoint_status_before_exiting(monkeypatch, environment, tmp_path, capsys):
    opener = MagicMock()
    opener.open.side_effect = _http_error(503)
    monkeypatch.setattr(probe.urllib.request, "build_opener", lambda *handlers: opener)
    output = tmp_path / "github_output"
    monkeypatch.setattr(probe.os, "environ", {**environment, "GITHUB_OUTPUT": str(output)})
    monkeypatch.setattr(probe.sys, "argv", ["probe_with_oauth.py", "--", "--server-card"])

    assert probe.main() == 1

    err = capsys.readouterr().err
    assert "OAuth token endpoint returned HTTP 503" in err
    assert "auth_provider_unavailable" in err
    recorded = output.read_text()
    assert "probe_outcome=auth_provider_unavailable\n" in recorded
    assert "probe_detail=OAuth token endpoint returned HTTP 503" in recorded
    assert "private-test-value" not in recorded + err


def test_main_classifies_a_failed_mcp_probe_after_a_token_was_issued(monkeypatch, environment, tmp_path, capsys):
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(
        dict(access_token="fresh-token", token_type="Bearer", expires_in=300)
    ).encode()
    monkeypatch.setattr(probe.urllib.request, "build_opener", lambda *handlers: opener)
    output = tmp_path / "github_output"
    monkeypatch.setattr(probe.os, "environ", {**environment, "GITHUB_OUTPUT": str(output)})
    monkeypatch.setattr(probe.sys, "argv", ["probe_with_oauth.py", "--", "--server-card"])
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: MagicMock(returncode=1))

    assert probe.main() == 1

    assert "probe_outcome=probe_failed\n" in output.read_text()
    assert "MCP probe exited 1" in capsys.readouterr().err


def test_main_flags_a_missing_probe_credential_as_configuration(monkeypatch, tmp_path, capsys):
    output = tmp_path / "github_output"
    monkeypatch.setattr(probe.os, "environ", {"GITHUB_OUTPUT": str(output)})
    monkeypatch.setattr(probe.sys, "argv", ["probe_with_oauth.py", "--", "--server-card"])
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: pytest.fail("probe must not run without a credential"))

    assert probe.main() == 1

    assert "probe_outcome=probe_configuration\n" in output.read_text()
    assert "RAILWAY_MCP_BEARER_TOKEN is empty" in capsys.readouterr().err
