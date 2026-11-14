"""One step from install to the dashboard, without the dev key ever leaving the terminal."""

from __future__ import annotations

import importlib.util
import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._ui_handoff import one_step_ui_command

_SECRET = "abk_test_only_dev_key_value_0123456789"
_AUTH_ENV_NAMES = (
    "AGENT_BOM_API_KEY",
    "AGENT_BOM_API_KEYS",
    "AGENT_BOM_OIDC_ISSUER",
    "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
    "AGENT_BOM_TRUST_PROXY_AUTH",
    "AGENT_BOM_SCIM_BEARER_TOKEN",
    "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
    "AGENT_BOM_NO_AUTO_DEV_KEY",
    "AGENT_BOM_LOG_JSON",
)


def _hide_ui_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: None if name in {"fastapi", "uvicorn"} else real(name, *a, **k))


def _clean_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _AUTH_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def test_one_step_command_pins_a_released_version() -> None:
    assert one_step_ui_command("up", version="0.115.0") == "uvx --from 'agent-bom[ui]==0.115.0' agent-bom up"
    assert (
        one_step_ui_command("serve", ["--port", "9000"], version="0.115.0.dev3") == "uvx --from 'agent-bom[ui]' agent-bom serve --port 9000"
    )


@pytest.mark.parametrize("verb", ["up", "serve"])
def test_missing_ui_extra_prints_the_single_command_that_works(monkeypatch: pytest.MonkeyPatch, verb: str) -> None:
    _hide_ui_extra(monkeypatch)

    result = CliRunner().invoke(main, [verb, "--port", "9100", "--api-key", "operator-secret"])

    assert result.exit_code == 1
    assert "--from 'agent-bom[ui]" in result.output
    assert f"agent-bom {verb} --port 9100" in result.output
    assert "operator-secret" not in result.output
    assert "pip install 'agent-bom[ui]'" in result.output


def _serve(monkeypatch: pytest.MonkeyPatch, args: list[str], *, tty: bool):
    _clean_auth_env(monkeypatch)
    with (
        patch("agent_bom.cli._server._generate_dev_api_key", return_value=_SECRET),
        patch("agent_bom.cli._ui_handoff.interactive_terminal", return_value=tty),
        patch("agent_bom.cli._ui_handoff.dashboard_bundled", return_value=True),
        patch("agent_bom.api.server.configure_api"),
        patch("agent_bom.api.server.set_dev_api_key"),
        patch("uvicorn.run") as run,
    ):
        result = CliRunner().invoke(main, ["up", *args])
    assert result.exit_code == 0, result.output
    assert run.called
    return result


def test_interactive_start_labels_the_url_and_the_dev_key(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _serve(monkeypatch, [], tty=True)

    assert "Open: http://127.0.0.1:8422/" in result.output
    assert "signs in automatically" in result.output
    assert f"Dev API key (this start only, loopback only): {_SECRET}" in result.output


def test_dev_key_is_withheld_when_stdout_is_not_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _serve(monkeypatch, [], tty=False)

    assert _SECRET not in result.output
    assert "Open: http://127.0.0.1:8422/" in result.output
    assert "withheld" in result.output


def test_log_json_never_contains_the_dev_key(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    log_file = tmp_path / "serve.log"
    monkeypatch.setenv("AGENT_BOM_LOG_FILE", str(log_file))

    result = _serve(monkeypatch, ["--log-json"], tty=True)

    assert _SECRET not in result.output
    assert _SECRET not in result.stderr
    assert not log_file.exists() or _SECRET not in log_file.read_text(encoding="utf-8")
    records = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
    assert any("Open: http://127.0.0.1:8422/" in record["msg"] for record in records), result.stderr


def test_quickstart_guidance_matches_the_automatic_dev_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_STATE_DIR", raising=False)

    result = CliRunner().invoke(main, ["quickstart", "--dry-run", "--offline"])

    assert result.exit_code == 0
    text = " ".join(result.output.split())
    assert "explicit local analyst role permits scans" not in text
    assert "signs in automatically" in text
    assert "dev API key" in text and "analyst role" in text


def test_quickstart_open_requires_run() -> None:
    result = CliRunner().invoke(main, ["quickstart", "--open"])

    assert result.exit_code != 0
    assert "--open requires --run" in result.output


def test_browser_opens_only_once_the_server_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    from agent_bom.cli import _ui_handoff

    opened: list[str] = []
    monkeypatch.setattr(_ui_handoff.webbrowser, "open", opened.append)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    try:
        thread = _ui_handoff.open_browser_when_ready("http://127.0.0.1/x", "127.0.0.1", port, timeout=5)
        listener.listen()
        thread.join(timeout=5)
    finally:
        listener.close()

    assert opened == ["http://127.0.0.1/x"]


def test_browser_is_not_opened_when_nothing_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    from agent_bom.cli import _ui_handoff

    opened: list[str] = []
    monkeypatch.setattr(_ui_handoff.webbrowser, "open", opened.append)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    _ui_handoff.open_browser_when_ready("http://127.0.0.1/x", "127.0.0.1", port, timeout=0.5).join(timeout=3)

    assert opened == []
