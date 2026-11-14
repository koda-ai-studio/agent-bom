"""A scan push too large for the control plane fails with a clear, actionable message, never a silent drop."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from agent_bom import config, push
from agent_bom.api import middleware_body

PUSH_URL = "http://localhost:8422/v1/results/push"


def _report(agents: int, padding: int = 400) -> dict:
    return {"agents": [{"name": f"agent-{index}", "notes": "x" * padding} for index in range(agents)], "blast_radius": []}


def _client_factory(handler):
    calls: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    def create_client(**_kwargs):
        return httpx.AsyncClient(transport=httpx.MockTransport(respond))

    return create_client, calls


def test_the_ceiling_is_one_shared_constant_for_client_and_server() -> None:
    assert middleware_body.RESULT_PUSH_JSONB_CEILING_BYTES is push.RESULT_PUSH_JSONB_CEILING_BYTES
    assert push.RESULT_PUSH_JSONB_CEILING_BYTES == 240 * 1024 * 1024


def test_a_report_over_the_ceiling_is_refused_before_any_upload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(push, "RESULT_PUSH_JSONB_CEILING_BYTES", 20_000)
    create_client, calls = _client_factory(lambda _request: httpx.Response(201, json={}))
    monkeypatch.setattr("agent_bom.http_client.create_client", create_client)

    with pytest.raises(push.PushTooLargeError) as raised:
        push.push_results(PUSH_URL, _report(100))

    assert calls == [], "an upload no control plane can store must not be sent"
    error = raised.value
    assert error.agents == 100 and error.max_bytes == 20_000 and error.decoded_bytes > 40_000
    message = str(error)
    assert "100 agents" in message and "no control plane accepts" in message
    assert f"at most {error.agents_per_push} agents" in message
    # Splitting by the recommendation must fit: per-agent size times the advice stays under the limit.
    assert 0 < error.agents_per_push * (error.decoded_bytes / error.agents) <= error.max_bytes


def test_a_413_from_the_server_reports_its_budget_once_without_retrying(monkeypatch: pytest.MonkeyPatch) -> None:
    budget = 30_000
    create_client, calls = _client_factory(lambda _request: httpx.Response(413, json={"detail": "too large", "max_bytes": budget}))
    monkeypatch.setattr("agent_bom.http_client.create_client", create_client)

    with pytest.raises(push.PushTooLargeError) as raised:
        push.push_results(PUSH_URL, _report(100))

    assert len(calls) == 1
    error = raised.value
    assert error.max_bytes == budget and error.agents == 100
    assert "this control plane accepts at most" in str(error)
    assert error.agents_per_push * (error.decoded_bytes / error.agents) <= budget


def test_a_413_without_a_budget_still_names_the_report_size(monkeypatch: pytest.MonkeyPatch) -> None:
    create_client, _calls = _client_factory(lambda _request: httpx.Response(413, text="<html>proxy limit</html>"))
    monkeypatch.setattr("agent_bom.http_client.create_client", create_client)

    with pytest.raises(push.PushTooLargeError) as raised:
        push.push_results(PUSH_URL, _report(10))
    assert raised.value.max_bytes is None
    assert "10 agents" in str(raised.value) and "proxy" in str(raised.value)


def test_a_report_within_the_budget_is_pushed_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    create_client, calls = _client_factory(lambda _request: httpx.Response(201, json={"job_id": "j"}))
    monkeypatch.setattr("agent_bom.http_client.create_client", create_client)
    monkeypatch.setattr(config, "PUSH_GZIP", False)

    assert push.push_results(PUSH_URL, _report(3)) is True
    assert len(json.loads(calls[0].content)["agents"]) == 3


def test_connector_style_callers_get_a_failure_not_an_exception(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    monkeypatch.setattr(push, "RESULT_PUSH_JSONB_CEILING_BYTES", 2_000)
    create_client, calls = _client_factory(lambda _request: httpx.Response(201, json={}))
    monkeypatch.setattr("agent_bom.http_client.create_client", create_client)

    assert push.push_json(PUSH_URL, _report(20)) is None
    assert calls == []
    assert any("agents per push" in record.getMessage() for record in caplog.records)


def test_the_cli_prints_the_split_advice_and_fails_the_run(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from agent_bom.cli.agents import _post

    monkeypatch.setattr(push, "RESULT_PUSH_JSONB_CEILING_BYTES", 20_000)
    create_client, calls = _client_factory(lambda _request: httpx.Response(201, json={}))
    monkeypatch.setattr("agent_bom.http_client.create_client", create_client)
    monkeypatch.setattr(_post, "to_json", lambda _scan: _report(100))

    delivered = _post._push_report(SimpleNamespace(con=None, target_scope=None), object(), PUSH_URL, None, quiet=True)

    # Only the report-schema capability probe (GET /version) may precede the refusal; nothing is uploaded.
    assert delivered is False and [(call.method, call.url.path) for call in calls] in ([], [("GET", "/version")])
    err = capsys.readouterr().err
    assert "100 agents" in err and "agents per push" in err and "--inventory" in err


def test_a_413_from_another_endpoint_keeps_the_plain_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    create_client, calls = _client_factory(lambda _request: httpx.Response(413, json={"detail": "too large", "max_bytes": 10}))
    monkeypatch.setattr("agent_bom.http_client.create_client", create_client)

    assert push.push_results("http://localhost:8422/v1/fleet/sync", _report(3)) is False
    assert len(calls) == 1
