"""Alert (default) vs enforce injection protection against a malicious stdio MCP server."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agent_bom.runtime import detectors
from agent_bom.runtime.detectors import Alert, AlertSeverity
from agent_bom.runtime.injection_protection import (
    InjectionModeError,
    reject_unsupported_enforce,
    resolve_injection_mode,
)
from tests.test_proxy_characterization import _EXIT, FIXTURES, _call, _list, _run_scenario

MALICIOUS_SERVER = FIXTURES / "malicious_server.py"
_spec = importlib.util.spec_from_file_location("malicious_server_fixture", MALICIOUS_SERVER)
assert _spec and _spec.loader
malicious = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(malicious)

EXFIL_HOST = "exfil.invalid"


def _scenario(**kwargs):
    return {
        "server": MALICIOUS_SERVER,
        "kwargs": kwargs,
        "script": [
            (_list(1), True),
            (_call(2, "weather"), True),
            (_call(3, "add_numbers", {"a": 1, "b": 2}), True),
            (_call(4, "echo", {"text": "hi"}), True),
            _EXIT,
        ],
    }


def _by_id(frames):
    return {frame.get("id"): frame for frame in frames if isinstance(frame, dict) and "id" in frame}


def _alerts(observed):
    return [record for record in observed["audit"] if record.get("type") == "runtime_alert"]


def _tool_names(frame):
    return [tool["name"] for tool in frame["result"]["tools"]]


# --- configuration -----------------------------------------------------------------


def test_default_mode_is_alert():
    assert resolve_injection_mode(None, None) == "alert"
    assert resolve_injection_mode(None, {}) == "alert"


@pytest.mark.parametrize(
    ("flag", "policy", "expected"),
    [
        ("enforce", None, "enforce"),
        (" ENFORCE ", {}, "enforce"),
        (None, {"injection_mode": "enforce"}, "enforce"),
        ("alert", {"injection_mode": "enforce"}, "enforce"),
        ("enforce", {"injection_mode": "alert"}, "enforce"),
        ("alert", {"injection_mode": "alert"}, "alert"),
    ],
)
def test_strictest_source_wins(flag, policy, expected):
    assert resolve_injection_mode(flag, policy) == expected


@pytest.mark.parametrize(("flag", "policy"), [("block", None), (None, {"injection_mode": "on"}), (None, {"injection_mode": 1})])
def test_invalid_mode_rejected_without_echo(flag, policy):
    with pytest.raises(InjectionModeError) as exc:
        resolve_injection_mode(flag, policy)
    assert "block" not in str(exc.value) and "'on'" not in str(exc.value)


def test_enforce_and_log_only_are_contradictory():
    assert resolve_injection_mode(None, None, log_only=True) == "alert"
    with pytest.raises(InjectionModeError):
        resolve_injection_mode("enforce", None, log_only=True)
    with pytest.raises(InjectionModeError):
        resolve_injection_mode(None, {"injection_mode": "enforce"}, log_only=True)


def test_sse_proxy_refuses_enforce_policy():
    reject_unsupported_enforce({"injection_mode": "alert"})
    with pytest.raises(InjectionModeError):
        reject_unsupported_enforce({"injection_mode": "enforce"})


def test_alert_action_field_only_when_enforced():
    alert = Alert(detector="response_inspector", severity=AlertSeverity.HIGH, message="m")
    assert "action" not in alert.to_dict()
    alert.action = "blocked"
    assert alert.to_dict()["action"] == "blocked"


# --- stdio proxy -------------------------------------------------------------------


def test_default_alert_mode_passes_poison_through_but_alerts(tmp_path, monkeypatch):
    observed = _run_scenario("alert", _scenario(), tmp_path, monkeypatch)
    frames = _by_id(observed["client_frames"])
    assert "add_numbers" in _tool_names(frames[1])
    assert malicious.POISONED_DESCRIPTION in json.dumps(frames[1])
    assert frames[2]["result"]["content"][0]["text"] == malicious.INJECTED_TEXT
    assert frames[3]["result"]["content"][0]["text"] == "ok:add_numbers"
    alerts = _alerts(observed)
    injection = [a for a in alerts if a["details"].get("category") == "prompt_injection"]
    assert injection, "alert mode must still detect"
    assert all("action" not in a for a in alerts)


def _assert_enforced(observed):
    frames = _by_id(observed["client_frames"])
    assert _tool_names(frames[1]) == ["echo", "weather", "leak"]
    error = frames[2]["error"]
    assert error["code"] == -32001
    assert error["data"] == {
        "policy_source": "injection_protection",
        "action": "blocked",
        "detectors": ["response_inspector"],
        "categories": ["prompt_injection"],
    }
    assert "error" in frames[3] and "result" not in frames[3]
    assert frames[4]["result"]["content"][0]["text"] == "ok:echo"
    client_text = json.dumps(observed["client_frames"])
    assert EXFIL_HOST not in client_text
    assert "Ignore" not in client_text
    server_calls = [f.get("params", {}).get("name") for f in observed["server_frames"] if f.get("method") == "tools/call"]
    assert "add_numbers" not in server_calls
    assert EXFIL_HOST not in json.dumps(observed["audit"])
    actions = {(a["details"].get("tool"), a.get("action")) for a in _alerts(observed) if a.get("action")}
    assert ("add_numbers", "stripped") in actions
    assert ("weather", "blocked") in actions
    assert ("add_numbers", "blocked") in actions
    blocked_calls = [r for r in observed["audit"] if r.get("type") == "tools/call" and r.get("policy") == "blocked"]
    assert [r["tool"] for r in blocked_calls] == ["add_numbers"]


def test_enforce_flag_strips_poisoned_tool_and_blocks_injected_result(tmp_path, monkeypatch):
    _assert_enforced(_run_scenario("enforce", _scenario(injection_mode="enforce"), tmp_path, monkeypatch))


def test_enforce_policy_setting_is_equivalent_to_flag(tmp_path, monkeypatch):
    _assert_enforced(_run_scenario("enforce-policy", _scenario(policy={"injection_mode": "enforce"}), tmp_path, monkeypatch))


def test_enforce_keeps_credential_redaction(tmp_path, monkeypatch):
    spec = _scenario(injection_mode="enforce", detect_credentials=True)
    spec["script"] = [(_call(1, "leak"), True), _EXIT]
    observed = _run_scenario("enforce-leak", spec, tmp_path, monkeypatch)
    text = json.dumps(observed["client_frames"])
    assert malicious.SECRET not in text
    assert "REDACTED" in text


def _raise(*_args, **_kwargs):
    raise RuntimeError("detector exploded near secret-token-123")


def test_detector_failure_fails_open_with_alert_in_alert_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(detectors.ResponseInspector, "check", _raise)
    observed = _run_scenario("alert-fault", _scenario(), tmp_path, monkeypatch)
    frames = _by_id(observed["client_frames"])
    assert "add_numbers" in _tool_names(frames[1])
    assert frames[2]["result"]["content"][0]["text"] == malicious.INJECTED_TEXT
    faults = [a for a in _alerts(observed) if a["details"].get("category") == "detector_error"]
    assert faults and all("action" not in a for a in faults)
    assert all(a["details"]["error_type"] == "RuntimeError" for a in faults)
    assert "secret-token-123" not in json.dumps(observed["audit"])


def test_detector_failure_fails_closed_in_enforce_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(detectors.ResponseInspector, "check", _raise)
    observed = _run_scenario("enforce-fault", _scenario(injection_mode="enforce"), tmp_path, monkeypatch)
    frames = _by_id(observed["client_frames"])
    assert _tool_names(frames[1]) == []
    assert all("error" in frames[msg_id] for msg_id in (2, 3, 4))
    assert {(a["details"]["tool"], a["action"]) for a in _alerts(observed) if a["details"].get("category") == "detector_error"} == {
        ("echo", "stripped"),
        ("add_numbers", "stripped"),
        ("weather", "stripped"),
        ("leak", "stripped"),
    }
    unlisted = _scenario(injection_mode="enforce")
    unlisted["script"] = [(_call(1, "weather"), True), _EXIT]
    (tmp_path / "result").mkdir()
    observed = _run_scenario("enforce-fault-result", unlisted, tmp_path / "result", monkeypatch)
    error = _by_id(observed["client_frames"])[1]["error"]
    assert error["code"] == -32001
    assert error["data"]["categories"] == ["detector_error"]
    assert "Forecast" not in json.dumps(observed["client_frames"])
    assert "secret-token-123" not in json.dumps(observed)


def test_log_only_with_enforce_refuses_to_start(tmp_path, monkeypatch):
    with pytest.raises(InjectionModeError):
        _run_scenario("conflict", _scenario(injection_mode="enforce", log_only=True), tmp_path, monkeypatch)


# --- gateway -----------------------------------------------------------------------


def _gateway(**settings_kwargs):
    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

    events: list[dict] = []

    class Audit:
        async def admit_before_tool_execution(self, event):
            events.append(event)

        async def __call__(self, event):
            events.append(event)

    async def upstream(config, message, headers):
        if message.get("method") == "tools/list":
            return {"jsonrpc": "2.0", "id": message["id"], "result": {"tools": malicious.TOOLS}}
        name = message["params"]["name"]
        text = malicious.INJECTED_TEXT if name == "weather" else f"ok:{name}"
        return malicious.text_result(message["id"], text)

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="fixture", url="https://fixture.invalid/mcp")]),
        upstream_caller=upstream,
        audit_sink=Audit(),
        **({"policy": {}} | settings_kwargs),
    )
    return create_gateway_app(settings), events


def _post(client, msg_id, method, name=None):
    payload = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if name:
        payload["params"] = {"name": name, "arguments": {}}
    return client.post("/mcp/fixture", json=payload).json()


def _gateway_alerts(events):
    return [event["alert"] for event in events if event.get("action") == "gateway.injection_alert"]


def test_gateway_default_alerts_and_passes_through():
    app, events = _gateway()
    with TestClient(app) as client:
        listed = _post(client, 1, "tools/list")
        weather = _post(client, 2, "tools/call", "weather")
    assert "add_numbers" in _tool_names(listed)
    assert weather["result"]["content"][0]["text"] == malicious.INJECTED_TEXT
    alerts = _gateway_alerts(events)
    assert any(a["details"].get("category") == "prompt_injection" for a in alerts)
    assert all("action" not in a for a in alerts)


@pytest.mark.parametrize("source", ["setting", "policy"])
def test_gateway_enforce_strips_and_blocks(source):
    kwargs = {"injection_mode": "enforce"} if source == "setting" else {"policy": {"injection_mode": "enforce"}}
    app, events = _gateway(**kwargs)
    with TestClient(app) as client:
        listed = _post(client, 1, "tools/list")
        weather = _post(client, 2, "tools/call", "weather")
        echo = _post(client, 3, "tools/call", "echo")
    assert _tool_names(listed) == ["echo", "weather", "leak"]
    assert weather["error"]["data"]["action"] == "blocked"
    assert weather["error"]["data"]["detectors"] == ["response_inspector"]
    assert echo["result"]["content"][0]["text"] == "ok:echo"
    assert EXFIL_HOST not in json.dumps([listed, weather])
    assert EXFIL_HOST not in json.dumps(events)
    actions = {(a["details"].get("tool"), a.get("action")) for a in _gateway_alerts(events) if a.get("action")}
    assert actions == {("add_numbers", "stripped"), ("weather", "blocked")}
    typed = {e.get("data_action") for e in events if e.get("policy_source") == "injection_protection"}
    assert typed == {"poisoned_tools_stripped", "injected_result_blocked"}


def test_gateway_detector_failure_follows_profile(monkeypatch):
    monkeypatch.setattr(detectors.ResponseInspector, "check", _raise)
    app, _ = _gateway()
    with TestClient(app) as client:
        assert _post(client, 2, "tools/call", "weather")["result"]["content"][0]["text"] == malicious.INJECTED_TEXT
    app, events = _gateway(injection_mode="enforce")
    with TestClient(app) as client:
        assert _post(client, 2, "tools/call", "weather")["error"]["data"]["categories"] == ["detector_error"]
    assert "secret-token-123" not in json.dumps(events)


def test_gateway_rejects_unknown_injection_mode():
    with pytest.raises(ValueError, match="injection_mode"):
        _gateway(injection_mode="block")


def test_gateway_cli_and_helm_expose_the_flag():
    from click.testing import CliRunner

    from agent_bom.cli._gateway import serve_cmd

    help_text = CliRunner().invoke(serve_cmd, ["--help"]).output
    assert "--injection-mode" in help_text
    root = Path(__file__).resolve().parents[1]
    template = (root / "deploy/helm/agent-bom/templates/gateway-deployment.yaml").read_text()
    assert "--injection-mode" in template
    assert 'injectionMode: "alert"' in (root / "deploy/helm/agent-bom/values.yaml").read_text()


def test_proxy_cli_exposes_flag_and_rejects_sse_enforce():
    from click.testing import CliRunner

    from agent_bom.cli._runtime import proxy_cmd

    assert "--injection-mode" in CliRunner().invoke(proxy_cmd, ["--help"]).output
    result = CliRunner().invoke(proxy_cmd, ["--url", "http://127.0.0.1:9/mcp", "--injection-mode", "enforce"])
    assert result.exit_code == 2
    assert "SSE/HTTP" in result.output


def test_gateway_enforce_refuses_calls_to_withheld_tools():
    """A tool stripped from tools/list stays uncallable through the gateway (same envelope as the proxy)."""
    app, events = _gateway(injection_mode="enforce")
    with TestClient(app) as client:
        listed = _post(client, 1, "tools/list")
        poisoned = _post(client, 2, "tools/call", "add_numbers")
        echo = _post(client, 3, "tools/call", "echo")
    assert "add_numbers" not in _tool_names(listed)
    assert poisoned["error"]["code"] == -32001
    assert poisoned["error"]["data"] == {
        "policy_source": "injection_protection",
        "action": "blocked",
        "detectors": ["injection_protection"],
        "categories": ["withheld_tool"],
    }
    assert echo["result"]["content"][0]["text"] == "ok:echo"
    # The call never reached admission (and so never reached the upstream).
    assert not any(e.get("action") == "gateway.tool_call" and e.get("tool") == "add_numbers" for e in events)
    blocked = [a for a in _gateway_alerts(events) if a["details"].get("category") == "withheld_tool"]
    assert blocked and blocked[0]["action"] == "blocked" and blocked[0]["details"]["tool"] == "add_numbers"
    typed = [e for e in events if e.get("data_action") == "withheld_tool_call_blocked"]
    assert typed and typed[0]["decision"] == "deny" and typed[0]["policy_source"] == "injection_protection"


def test_gateway_alert_mode_never_withholds_calls():
    app, _events = _gateway()
    with TestClient(app) as client:
        _post(client, 1, "tools/list")
        assert _post(client, 2, "tools/call", "add_numbers")["result"]["content"][0]["text"] == "ok:add_numbers"


def test_injection_mode_help_states_the_enforce_threshold():
    from agent_bom.runtime.injection_protection import INJECTION_MODE_HELP

    assert "high" in INJECTION_MODE_HELP.lower() and "critical" in INJECTION_MODE_HELP.lower()
    assert "medium" in INJECTION_MODE_HELP.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(("mode", "forwarded"), [("alert", True), ("enforce", False)])
async def test_enforce_drops_unparsed_upstream_stdout_even_without_inline_scanning(mode, forwarded, monkeypatch):
    import io
    from types import SimpleNamespace

    from agent_bom.proxy_scanner import ScanConfig
    from agent_bom.runtime import proxy_relay
    from agent_bom.runtime.proxy_session import RelayOptions
    from tests.test_proxy_tool_catalog_paging import _session

    session, alerts = _session()
    session.scan_config = ScanConfig(enabled=False)
    session.options = RelayOptions(
        block_undeclared=False,
        log_only=False,
        rate_limit_threshold=0,
        alert_webhook=None,
        response_signing_key=None,
        policy_refresh_seconds=0,
        injection_mode=mode,
    )
    output = io.BytesIO()
    with monkeypatch.context() as scoped:
        scoped.setattr(proxy_relay.sys, "stdout", SimpleNamespace(buffer=output))
        await proxy_relay.relay_server_line(session, b"private plain text that is not JSON-RPC\n")
    assert bool(output.getvalue()) is forwarded
    if forwarded:
        assert alerts == []
    else:
        assert alerts[0].action == "blocked"
        assert alerts[0].details["category"] == "unparsed_stdout"
        assert "private plain text" not in json.dumps(alerts[0].to_dict())
