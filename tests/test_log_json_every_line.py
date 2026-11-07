"""Under ``--log-json`` every line the server writes is JSON, and a healthy local start does not warn."""

from __future__ import annotations

import importlib
import json
import logging
import logging.config
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from agent_bom.logging_config import JSONFormatter, api_log_config, json_logging_active, setup_logging

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _restore_logging():
    yield
    setup_logging(level="WARNING", json_output=False)
    logging.getLogger().handlers.clear()


def _uvicorn_config():
    uvicorn = pytest.importorskip("uvicorn")
    return uvicorn.config.LOGGING_CONFIG


def test_json_log_config_formats_uvicorn_and_root_loggers_as_json() -> None:
    config = api_log_config(_uvicorn_config(), json_output=True, level="INFO")

    for name in ("default", "access"):
        assert config["formatters"][name]["()"] == "agent_bom.logging_config.JSONFormatter"
    assert config["root"]["handlers"] == ["default"]
    assert "access_path" in config["handlers"]["access"]["filters"]


def test_plain_log_config_keeps_uvicorn_formatters() -> None:
    default = _uvicorn_config()
    config = api_log_config(default, json_output=False)
    assert config["formatters"] == {**default["formatters"]}
    assert "root" not in config


def test_access_record_is_structured_json_without_the_query() -> None:
    from agent_bom.logging_config import AccessLogPathFilter

    args = ("10.0.0.1:5", "GET", "/v1/jobs?token=s3cret", "1.1", 401)
    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d', args, None)
    AccessLogPathFilter().filter(record)
    entry = json.loads(JSONFormatter().format(record))

    assert entry["http"] == {"client": "10.0.0.1:5", "method": "GET", "path": "/v1/jobs", "version": "1.1", "status": 401}
    assert "s3cret" not in json.dumps(entry)


def test_env_var_turns_json_on_when_the_flag_is_off(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_LOG_JSON", "1")
    setup_logging(level="INFO", json_output=False)
    assert json_logging_active()


def test_runtime_summary_is_one_json_event_on_stderr_under_json(capsys) -> None:
    from agent_bom.output.brand_tokens import emit_cli_runtime_summary

    setup_logging(level="INFO", json_output=True)
    emit_cli_runtime_summary("agent-bom API", [("Bind", "http://127.0.0.1:1"), ("Storage", "In-memory")])
    captured = capsys.readouterr()

    assert captured.out == ""
    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["msg"] == "agent-bom API"
    assert event["context"] == {"Bind": "http://127.0.0.1:1", "Storage": "In-memory"}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("via_env", [False, True], ids=["flag", "env"])
def test_api_server_writes_only_json_lines(tmp_path: Path, via_env: bool) -> None:
    pytest.importorskip("uvicorn")
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENT_BOM_")}
    env.update({"HOME": str(tmp_path), "PYTHONPATH": str(ROOT / "src"), "AGENT_BOM_SKIP_UPDATE_CHECK": "1", "NO_COLOR": "1"})
    args = [sys.executable, "-m", "agent_bom", "api", "--port", str(port)]
    if via_env:
        env["AGENT_BOM_LOG_JSON"] = "1"
    else:
        args.append("--log-json")
    out, err = tmp_path / "out.log", tmp_path / "err.log"
    with out.open("wb") as stdout, err.open("wb") as stderr:
        proc = subprocess.Popen(args, cwd=tmp_path, env=env, stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2).read()
                    break
                except OSError:
                    if time.monotonic() > deadline or proc.poll() is not None:
                        pytest.fail(err.read_text(errors="replace")[-2000:])
                    time.sleep(0.25)
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/jobs?token=s3cret", timeout=5)
            except OSError:
                pass
        finally:
            proc.terminate()
            proc.wait(timeout=30)

    lines = [line for path in (out, err) for line in path.read_text(errors="replace").splitlines() if line.strip()]
    plain = []
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except ValueError:
            plain.append(line)
    assert not plain, "\n".join(plain[:20])
    access = [e for e in events if e.get("logger") == "uvicorn.access"]
    assert {e["http"]["path"] for e in access} >= {"/health", "/v1/jobs"}
    assert "s3cret" not in "\n".join(lines)
    assert any(e["msg"] == "agent-bom API" for e in events)
    noisy = [e for e in events if e["level"] == "WARNING" and ("rate_limit_key_rotation" in e["msg"] or "AUDIT_HMAC_KEY" in e["msg"])]
    assert not noisy, noisy


def test_ephemeral_rate_limit_key_is_info_in_single_process_local_mode(monkeypatch, caplog) -> None:
    from agent_bom.api import server

    monkeypatch.setattr(
        "agent_bom.api.middleware.get_rate_limit_key_status",
        lambda: {"status": "ephemeral", "severity": "info", "age_days": None, "message": "local"},
    )
    caplog.set_level(logging.INFO, logger="agent_bom.api.server")
    server._log_rate_limit_key_status()
    records = [r for r in caplog.records if "rate_limit_key_rotation" in r.getMessage()]
    assert [r.levelno for r in records] == [logging.INFO]


def test_ephemeral_rate_limit_key_still_warns_in_production(monkeypatch, caplog) -> None:
    from agent_bom.api import server

    monkeypatch.setattr(
        "agent_bom.api.middleware.get_rate_limit_key_status",
        lambda: {"status": "ephemeral", "severity": "warning", "age_days": None, "message": "set it"},
    )
    caplog.set_level(logging.INFO, logger="agent_bom.api.server")
    server._log_rate_limit_key_status()
    records = [r for r in caplog.records if "rate_limit_key_rotation" in r.getMessage()]
    assert [r.levelno for r in records] == [logging.WARNING]


@pytest.fixture
def fresh_audit_log(monkeypatch):
    names = ("AGENT_BOM_AUDIT_HMAC_KEY", "AGENT_BOM_AUDIT_HMAC_KEY_FILE", "AGENT_BOM_REQUIRE_AUDIT_HMAC", "AGENT_BOM_DB")
    for name in (*names, "AGENT_BOM_AUDIT_DB", "AGENT_BOM_POSTGRES_URL"):
        monkeypatch.delenv(name, raising=False)
    from agent_bom.api import audit_log

    module = importlib.reload(audit_log)
    yield module
    importlib.reload(audit_log)


def test_startup_with_in_memory_audit_does_not_warn_about_the_ephemeral_key(fresh_audit_log, caplog) -> None:
    caplog.set_level(logging.INFO, logger="agent_bom.api.audit_log")
    fresh_audit_log.warn_if_ephemeral_hmac_key()
    hmac = [r for r in caplog.records if "AGENT_BOM_AUDIT_HMAC_KEY not set" in r.getMessage()]
    assert [r.levelno for r in hmac] == [logging.INFO]


def test_startup_with_a_durable_audit_store_warns_about_the_ephemeral_key(fresh_audit_log, monkeypatch, caplog, tmp_path) -> None:
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "cp.db"))
    caplog.set_level(logging.INFO, logger="agent_bom.api.audit_log")
    fresh_audit_log.warn_if_ephemeral_hmac_key()
    hmac = [r for r in caplog.records if "AGENT_BOM_AUDIT_HMAC_KEY not set" in r.getMessage()]
    assert [r.levelno for r in hmac] == [logging.WARNING]
