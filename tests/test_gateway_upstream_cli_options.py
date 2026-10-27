"""Operator tuning reaches validated gateway settings before serving traffic."""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom.cli._gateway import gateway_group

OPTIONS = {
    "upstream_http_max_connections": 150,
    "upstream_http_max_keepalive_connections": 40,
    "upstream_http_timeout_seconds": 12.5,
    "upstream_failure_threshold": 5,
    "upstream_circuit_cooldown_seconds": 8.5,
}


@pytest.mark.parametrize("mode", ["flags", "environment", "precedence"])
def test_tuning_values_reach_gateway_settings(tmp_path, mode):
    source = tmp_path / "upstreams.yaml"
    source.write_text("upstreams: []\n")
    args = ["serve", "--upstreams", str(source), "--bind", "127.0.0.1:8090"]
    env = {}
    if mode != "flags":
        env = {"AGENT_BOM_GATEWAY_" + key.upper(): str(value if mode == "environment" else 1) for key, value in OPTIONS.items()}
    if mode != "environment":
        for key, value in OPTIONS.items():
            args.extend(["--" + key.replace("_", "-"), str(value)])
    with patch("agent_bom.gateway_server.create_gateway_app") as create, patch("uvicorn.run") as run:
        result = CliRunner().invoke(gateway_group, args, env=env)
    assert result.exit_code == 0, result.output
    assert run.call_count == 1
    settings = create.call_args.args[0]
    for key, value in OPTIONS.items():
        assert getattr(settings, key) == value


@pytest.mark.parametrize(
    "args",
    [
        ["--upstream-http-max-connections", "0"],
        ["--upstream-http-max-keepalive-connections", "-1"],
        ["--upstream-http-timeout-seconds", "0"],
        ["--upstream-http-timeout-seconds", "nan"],
        ["--upstream-circuit-cooldown-seconds", "inf"],
        ["--upstream-circuit-cooldown-seconds", "-1"],
        ["--upstream-failure-threshold", "0"],
        ["--upstream-http-max-connections", "2", "--upstream-http-max-keepalive-connections", "3"],
    ],
)
def test_invalid_tuning_rejected_before_discovery_or_listener(args):
    with patch("agent_bom.gateway_upstreams.fetch_discovered_upstreams") as discovery, patch("uvicorn.run") as run:
        result = CliRunner().invoke(gateway_group, ["serve", "--from-control-plane", "https://control.example.test", *args])
    assert result.exit_code != 0
    assert "No such option" not in result.output
    assert "upstream_" in result.output
    discovery.assert_not_called()
    run.assert_not_called()


def test_help_documents_flags_defaults_and_environment():
    result = CliRunner().invoke(gateway_group, ["serve", "--help"])
    assert result.exit_code == 0
    for key in OPTIONS:
        assert "--" + key.replace("_", "-") in result.output
        assert "AGENT_BOM_GATEWAY_" + key.upper() in "".join(result.output.split())
