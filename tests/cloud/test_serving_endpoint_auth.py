"""Bearer-token auth for protected serving endpoints.

The token comes only from a named ``AGENT_BOM_SERVING_TOKEN_*`` variable or its
``*_FILE`` path, is sent only to the endpoint it is paired with, and never
appears in evidence, warnings, the report or CLI output.
"""

from __future__ import annotations

import json
import secrets

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cloud.serving_runtimes import probe_endpoint
from tests._serving_runtime_fixtures import SCENARIOS, FixtureOptions, serving_fixture

_ENV = "AGENT_BOM_SERVING_TOKEN_VLLM_PROD"
_TIMEOUT = 0.5


def _token() -> str:
    return "-".join(["fixture", secrets.token_hex(12)])


def _auth_headers(seen: list) -> list[str | None]:
    return [headers.get("authorization") for _method, _path, headers in seen]


def test_token_from_env_unlocks_a_protected_endpoint_without_entering_evidence(monkeypatch):
    token = _token()
    monkeypatch.setenv(_ENV, token)
    seen: list = []
    with serving_fixture(SCENARIOS["vllm"]["success"], FixtureOptions(seen=seen, require_bearer=token)) as url:
        observation = probe_endpoint("vllm", url, timeout=_TIMEOUT, token_env=_ENV)

    assert observation.status == "success"
    assert _auth_headers(seen) == [f"Bearer {token}", f"Bearer {token}"]
    from agent_bom.cloud.serving_runtimes import serving_evidence

    evidence = serving_evidence(observation, observation.models[0])
    assert evidence["collection"]["request_identity"] == "bearer"
    assert "authentication" in evidence["collection"]["not_collected"]
    assert token not in json.dumps(evidence)
    assert token not in repr(observation)


def test_token_file_is_read_and_wins_over_the_plain_variable(monkeypatch, tmp_path):
    token = _token()
    secret_file = tmp_path / "serving-token"
    secret_file.write_text(token + "\n", encoding="utf-8")
    monkeypatch.setenv(_ENV, "stale-" + _token())
    monkeypatch.setenv(f"{_ENV}_FILE", str(secret_file))
    with serving_fixture(SCENARIOS["tgi"]["success"], FixtureOptions(require_bearer=token)) as url:
        observation = probe_endpoint("tgi", url, timeout=_TIMEOUT, token_env=_ENV)
    assert observation.status == "success"


def test_rejected_token_reads_as_denied_and_is_not_echoed(monkeypatch):
    token = _token()
    monkeypatch.setenv(_ENV, token)
    with serving_fixture(SCENARIOS["vllm"]["success"], FixtureOptions(require_bearer="other-" + _token())) as url:
        observation = probe_endpoint("vllm", url, timeout=_TIMEOUT, token_env=_ENV)
    assert observation.status == "denied"
    assert "bearer token was rejected" in observation.detail
    assert token not in observation.detail


def test_missing_token_fails_closed_before_any_request(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    monkeypatch.delenv(f"{_ENV}_FILE", raising=False)
    seen: list = []
    with serving_fixture(SCENARIOS["vllm"]["success"], FixtureOptions(seen=seen)) as url:
        observation = probe_endpoint("vllm", url, timeout=_TIMEOUT, token_env=_ENV)
    assert observation.status == "unavailable"
    assert _ENV in observation.detail
    assert seen == []


def test_missing_token_file_names_the_path_variable_only(monkeypatch, tmp_path):
    monkeypatch.setenv(f"{_ENV}_FILE", str(tmp_path / "absent"))
    observation = probe_endpoint("vllm", "http://127.0.0.1:9", timeout=_TIMEOUT, token_env=_ENV)
    assert observation.status == "unavailable"
    assert f"{_ENV}_FILE" in observation.detail


@pytest.mark.parametrize("bad", ["two words", "line\nbreak", "tab\tchar"])
def test_tokens_that_could_inject_headers_are_refused(monkeypatch, bad):
    monkeypatch.setenv(_ENV, bad)
    seen: list = []
    with serving_fixture(SCENARIOS["vllm"]["success"], FixtureOptions(seen=seen)) as url:
        observation = probe_endpoint("vllm", url, timeout=_TIMEOUT, token_env=_ENV)
    assert observation.status == "unavailable"
    assert bad not in observation.detail
    assert seen == []


def test_a_token_is_never_sent_in_cleartext_off_loopback(monkeypatch):
    monkeypatch.setenv(_ENV, _token())
    observation = probe_endpoint("vllm", "http://10.0.0.5:8000", timeout=_TIMEOUT, token_env=_ENV)
    assert observation.status == "unavailable"
    assert "https" in observation.detail


@pytest.mark.parametrize(
    "name", ["OPENAI_API_KEY", "AGENT_BOM_API_KEY", "AGENT_BOM_SERVING_TOKEN_", "AGENT_BOM_SERVING_TOKEN_X_FILE", "lower"]
)
def test_only_dedicated_serving_token_variables_are_accepted(name):
    with pytest.raises(ValueError, match="AGENT_BOM_SERVING_TOKEN_"):
        probe_endpoint("vllm", "http://127.0.0.1:9", timeout=_TIMEOUT, token_env=name)


def test_redirect_is_not_followed_so_the_token_cannot_leave(monkeypatch):
    token = _token()
    monkeypatch.setenv(_ENV, token)
    elsewhere_seen: list = []
    with serving_fixture(SCENARIOS["vllm"]["success"], FixtureOptions(seen=elsewhere_seen)) as elsewhere:
        routes = {("GET", "/v1/models"): (302, {}, 0.0)}
        redirect = FixtureOptions(response_headers={("GET", "/v1/models"): {"Location": f"{elsewhere}/v1/models"}})
        with serving_fixture(routes, redirect) as url:
            observation = probe_endpoint("vllm", url, timeout=_TIMEOUT, token_env=_ENV)
    assert observation.status == "unavailable"
    assert "HTTP 302" in observation.detail
    assert elsewhere_seen == []


# ── CLI wiring ──────────────────────────────────────────────────────────────


def _scan(tmp_path, args: list[str], env: dict[str, str]) -> tuple[dict, str]:
    out = tmp_path / "report.json"
    result = CliRunner().invoke(
        main, ["scan", "--no-scan", "--quiet", "-f", "json", "-o", str(out), *args], env={"HOME": str(tmp_path), **env}
    )
    assert out.exists(), result.output
    return json.loads(out.read_text()), result.output


def test_cli_sends_the_token_only_to_its_paired_endpoint(tmp_path):
    token = _token()
    protected_seen: list = []
    open_seen: list = []
    with (
        serving_fixture(SCENARIOS["vllm"]["success"], FixtureOptions(seen=protected_seen, require_bearer=token)) as protected,
        serving_fixture(SCENARIOS["llamacpp"]["success"], FixtureOptions(seen=open_seen)) as open_url,
    ):
        report, output = _scan(
            tmp_path,
            [
                "--serving-endpoint",
                f"vllm={protected}",
                "--serving-endpoint",
                f"llamacpp={open_url}",
                "--serving-token-env",
                f"{protected}/={_ENV}",
            ],
            {_ENV: token},
        )
    runtimes = {
        a["metadata"]["serving_evidence"]["runtime"]["name"]: a
        for a in report["agents"]
        if (a.get("metadata") or {}).get("serving_evidence")
    }
    assert set(runtimes) == {"vllm", "llamacpp"}
    assert runtimes["vllm"]["metadata"]["serving_evidence"]["collection"]["request_identity"] == "bearer"
    assert runtimes["llamacpp"]["metadata"]["serving_evidence"]["collection"]["request_identity"] == "anonymous"
    assert all(header == f"Bearer {token}" for header in _auth_headers(protected_seen))
    assert _auth_headers(open_seen) == [None, None]
    assert token not in json.dumps(report)
    assert token not in output


def test_cli_refuses_a_token_pairing_for_an_endpoint_that_is_not_probed():
    result = CliRunner().invoke(
        main,
        ["scan", "--dry-run", "--serving-endpoint", "vllm=http://127.0.0.1:8000", "--serving-token-env", f"http://127.0.0.1:8001={_ENV}"],
    )
    assert result.exit_code == 2
    assert "--serving-token-env" in result.output


def test_cli_refuses_a_raw_token_where_a_variable_name_belongs():
    raw = "sk-" + secrets.token_hex(8)
    result = CliRunner().invoke(
        main,
        ["scan", "--dry-run", "--serving-endpoint", "vllm=http://127.0.0.1:8000", "--serving-token-env", f"http://127.0.0.1:8000={raw}"],
    )
    assert result.exit_code == 2
    assert raw not in result.output


def test_dry_run_names_the_variable_never_a_value(tmp_path):
    token = _token()
    result = CliRunner().invoke(
        main,
        ["scan", "--dry-run", "--serving-endpoint", "vllm=http://127.0.0.1:8000", "--serving-token-env", f"http://127.0.0.1:8000={_ENV}"],
        env={_ENV: token},
    )
    assert result.exit_code == 0, result.output
    assert f"bearer token from {_ENV}" in result.output
    assert token not in result.output


def test_there_is_no_option_that_takes_a_token_value():
    help_text = CliRunner().invoke(main, ["scan", "--help-all"], terminal_width=200).output
    assert "--serving-token-env" in help_text
    assert "--serving-token " not in help_text
    assert "--serving-token=" not in help_text
