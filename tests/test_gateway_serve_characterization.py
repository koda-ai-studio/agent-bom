"""`gateway serve` wiring: every option lands in GatewaySettings, the summary and uvicorn."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom.cli._gateway import serve_cmd

UPSTREAMS = "upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n"


def _write(tmp_path: Path, name: str, payload: object) -> str:
    path = tmp_path / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return str(path)


def _invoke(args: list[str]):
    with (
        patch("agent_bom.gateway_server.create_gateway_app") as create_app,
        patch("uvicorn.run") as run,
    ):
        create_app.return_value = object()
        result = CliRunner().invoke(serve_cmd, args)
    return result, create_app, run


def test_full_option_set_reaches_settings_summary_and_uvicorn(tmp_path, monkeypatch):
    for var in ("AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON", "AGENT_BOM_GATEWAY_BEARER_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    upstreams = _write(tmp_path, "upstreams.yaml", UPSTREAMS)
    policy = _write(tmp_path, "policy.json", {"rules": [{"id": "no-delete", "action": "block", "block_tools": ["delete"]}]})
    bundle = _write(tmp_path, "bundle.json", {"policies": [{"id": "a"}, {"id": "b"}, "skip-me"]})
    firewall = _write(tmp_path, "firewall.json", {"default_decision": "deny", "enforcement_mode": "dry_run", "rules": []})
    scopes = _write(tmp_path, "scopes.json", {"fs.write": ["tools:write", " "], "read": "tools:read"})

    result, create_app, run = _invoke(
        [
            "--bind",
            "127.0.0.1:8091",
            "--upstreams",
            upstreams,
            "--policy",
            policy,
            "--policy-reload-seconds",
            "5",
            "--policy-bundle",
            bundle,
            "--firewall-policy",
            firewall,
            "--firewall-policy-reload-seconds",
            "7",
            "--tool-scope-map",
            scopes,
            "--enable-dlp",
            "--dlp-mode",
            "enforce",
            "--dlp-pii-action",
            "block",
            "--injection-mode",
            "enforce",
            "--a2a-mutual-auth-enforcement",
            "warn",
            "--drift-enforcement",
            "warn",
            "--log-level",
            "warning",
        ]
    )

    assert result.exit_code == 0, result.output
    settings = create_app.call_args.args[0]
    assert settings.registry.names() == ["jira"]
    assert settings.policy["rules"][0]["id"] == "no-delete"
    assert settings.control_plane_policies == [{"id": "a"}, {"id": "b"}]
    assert settings.tool_scope_map == {"fs.write": ["tools:write"], "read": ["tools:read"]}
    assert settings.audit_sink is None
    assert settings.oauth_as is None
    assert settings.listener_host == "127.0.0.1"
    assert settings.policy_path == Path(policy)
    assert settings.policy_reload_interval_seconds == 5
    assert settings.firewall_policy_path == Path(firewall)
    assert settings.firewall_policy_reload_interval_seconds == 7
    assert (settings.dlp_enabled, settings.dlp_mode, settings.dlp_pii_action) == (True, "enforce", "block")
    assert settings.injection_mode == "enforce"
    assert settings.a2a_mutual_auth_enforcement_mode == "warn"
    assert settings.drift_enforcement_mode == "warn"
    assert settings.graph_reachability_bundle_signing_key is None
    assert settings.graph_reachability_bundle_bearer_token == ""

    output = result.output
    assert "loaded 2 control-plane policy/policies from" in output
    assert "loaded OAuth scope requirements for 2 tool(s)" in output
    assert "http://127.0.0.1:8091" in output
    assert "Policy hot reload: enabled every 5s" in output
    assert "0 rule(s) (default=deny, mode=dry_run)" in output
    assert "Firewall hot reload: enabled every 7s" in output
    assert output.index("loaded 2 control-plane") < output.index("loaded OAuth scope") < output.index("http://127.0.0.1:8091")

    run.assert_called_once_with(create_app.return_value, host="127.0.0.1", port=8091, log_level="warning", proxy_headers=False)


def test_default_settings_without_optional_inputs(tmp_path):
    result, create_app, run = _invoke(["--bind", "127.0.0.1:8090", "--upstreams", _write(tmp_path, "u.yaml", UPSTREAMS)])
    assert result.exit_code == 0, result.output
    settings = create_app.call_args.args[0]
    assert settings.policy == {}
    assert settings.control_plane_policies == []
    assert settings.tool_scope_map == {}
    assert settings.injection_mode == "alert"
    assert settings.dlp_enabled is False
    assert "Firewall" not in result.output
    assert "Policy reload" not in result.output


@pytest.mark.parametrize(
    "extra,message",
    [
        (["--tool-scope-map", "scopes"], "--tool-scope-map value for 'bad' must be a string or list of strings"),
        (["--policy-bundle", "bundle"], "--policy-bundle must be a JSON list of policies"),
        (["--firewall-policy", "firewall"], "firewall policy invalid:"),
        (["--firewall-policy-reload-seconds", "3"], "--firewall-policy-reload-seconds requires --firewall-policy"),
        (["--policy-reload-seconds", "-1"], "--policy-reload-seconds must be >= 0"),
        (["--graph-reachability-bundle-poll-seconds", "-1"], "--graph-reachability-bundle-poll-seconds must be >= 0"),
    ],
)
def test_invalid_inputs_fail_before_the_app_is_built(tmp_path, extra, message):
    files = {
        "scopes": _write(tmp_path, "scopes.json", {"bad": 3}),
        "bundle": _write(tmp_path, "bundle.json", {"policies": "nope"}),
        "firewall": _write(tmp_path, "firewall.json", {"default_decision": "maybe"}),
    }
    args = [files.get(item, item) for item in extra]
    result, create_app, run = _invoke(["--bind", "127.0.0.1:8090", "--upstreams", _write(tmp_path, "u.yaml", UPSTREAMS), *args])
    assert result.exit_code == 1
    assert message in result.output
    create_app.assert_not_called()
    run.assert_not_called()


def test_missing_upstream_sources_exits_2():
    result, create_app, _ = _invoke(["--bind", "127.0.0.1:8090"])
    assert result.exit_code == 2
    assert "pass --upstreams or --from-control-plane" in result.output
    create_app.assert_not_called()
