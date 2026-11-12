"""A malformed endpoint URL is a classified outcome, never an uncaught exception."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cloud import discover_from_provider, ollama
from agent_bom.cloud.serving_runtimes import _ProbeError, _request, normalize_endpoint, probe_endpoint
from agent_bom.security import SecurityError, validate_url

BAD_PORTS = [
    "http://127.0.0.1:bad",
    "http://127.0.0.1:70000",
    "http://127.0.0.1:0",
    "http://127.0.0.1:+80",
    "http://127.0.0.1:-1",
    "http://[::1]:x",
    "http://127.0.0.1:٣",
]


@pytest.mark.parametrize("endpoint", BAD_PORTS)
def test_malformed_port_is_unavailable_before_any_request(endpoint):
    with patch("httpx.Client.stream") as stream:
        observation = probe_endpoint("vllm", endpoint, timeout=0.1)
    stream.assert_not_called()
    assert observation.status == "unavailable"
    assert observation.endpoint == ""
    assert "port" in observation.detail


@pytest.mark.parametrize("endpoint", BAD_PORTS)
def test_normalize_endpoint_refuses_malformed_port(endpoint):
    with pytest.raises(_ProbeError) as raised:
        normalize_endpoint(endpoint)
    assert raised.value.status == "unavailable"


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:1", "http://127.0.0.1:65535", "http://[::1]:8000", "http://127.0.0.1"])
def test_valid_ports_still_normalize(endpoint):
    assert normalize_endpoint(endpoint) == endpoint


def test_discover_returns_one_warning_for_a_malformed_port():
    agents, warnings = discover_from_provider("serving", runtime="vllm", endpoint="http://127.0.0.1:bad", timeout=0.1)
    assert agents == []
    assert len(warnings) == 1 and "port" in warnings[0]


def test_an_invalid_url_raised_by_the_client_is_classified():
    client = MagicMock()
    client.stream.side_effect = httpx.InvalidURL("Invalid port: 'bad'")
    with pytest.raises(_ProbeError) as raised:
        _request(client, "GET", "http://127.0.0.1:8000/v1/models")
    assert raised.value.status == "unavailable"


def test_cli_rejects_a_malformed_port_as_a_usage_error():
    result = CliRunner().invoke(main, ["scan", "--dry-run", "--serving-endpoint", "vllm=http://127.0.0.1:bad"])
    assert result.exit_code == 2, result.output
    assert "--serving-endpoint" in result.output
    assert "port" in result.output


def test_cli_rejects_a_credentialed_endpoint_without_echoing_the_secret():
    result = CliRunner().invoke(main, ["scan", "--dry-run", "--serving-endpoint", "vllm=http://user:s3cr3t@127.0.0.1:8000"])
    assert result.exit_code == 2, result.output
    assert "s3cr3t" not in result.output


@pytest.mark.parametrize("url", ["http://127.0.0.1:bad/x", "http://127.0.0.1:99999/x", "https://example.com:0/x"])
def test_outbound_url_policy_refuses_a_malformed_port(url):
    with pytest.raises(SecurityError) as raised:
        validate_url(url, allowed_schemes=("http", "https"), allow_private=True)
    assert "port" in str(raised.value)


def test_ollama_host_with_a_malformed_port_is_reported_not_raised(monkeypatch, tmp_path):
    monkeypatch.setattr(ollama, "_MANIFEST_DIR", tmp_path / "absent")
    agents, warnings = ollama.discover(host="http://127.0.0.1:bad", timeout=0.1)
    assert agents == []
    assert warnings
