"""Every provider call leaves one audit record; none of them holds prompt text."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from agent_bom.ai_components import call_audit, providers
from agent_bom.ai_components.call_state import AICallBudget, EnrichmentTask


class _FakeResponse:
    status_code = 200

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def json(self) -> dict:
        return self._payload


@pytest.fixture()
def records():
    captured: list[call_audit.AICallRecord] = []
    remove = call_audit.register_ai_call_sink(captured.append)
    yield captured
    remove()
    call_audit.reset_digest_cache()


def _client(payload: dict | Exception):
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    if isinstance(payload, Exception):
        client.post.side_effect = payload
    else:
        client.post.return_value = _FakeResponse(payload)
    client.get.return_value = _FakeResponse({"models": [{"name": "m:latest", "digest": "sha256-abc"}]})
    return client


OK = {"message": {"content": '{"ok":true}'}, "prompt_eval_count": 11, "eval_count": 7}


@pytest.mark.asyncio
async def test_ollama_call_records_identity_tokens_hashes_and_never_the_prompt(records) -> None:
    secret_prompt = "VERY-DISTINCTIVE-PROMPT-TEXT"
    with patch("httpx.AsyncClient", return_value=_client(OK)), call_audit.ai_call_scope(tenant_id="t-1", actor="alice"):
        text = await providers._call_llm(secret_prompt, "ollama/m:latest", task=EnrichmentTask.TRIAGE, system="SYSTEM-RULES-TEXT")
    assert text == '{"ok":true}'
    [record] = records
    assert (record.tenant_id, record.actor, record.task, record.provider, record.model) == (
        "t-1",
        "alice",
        "triage",
        "ollama",
        "ollama/m:latest",
    )
    assert record.model_digest == "sha256-abc"
    assert record.prompt_tokens == 11 and record.completion_tokens == 7
    assert record.outcome == "ok" and record.guard_rejected is False
    assert record.latency_ms >= 0
    assert record.response_sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert len(record.prompt_sha256) == 64
    serialized = json.dumps(record.to_details())
    assert secret_prompt not in serialized and "SYSTEM-RULES-TEXT" not in serialized


@pytest.mark.asyncio
async def test_system_message_and_schema_reach_ollama_and_change_the_cache_key(records) -> None:
    client = _client(OK)
    with patch("httpx.AsyncClient", return_value=client):
        await providers._call_llm("p", "ollama/m:latest", system="rules", response_schema={"type": "object"}, num_ctx=8192)
    body = client.post.call_args.kwargs["json"]
    assert body["messages"][0] == {"role": "system", "content": "rules"}
    assert body["format"] == {"type": "object"}
    assert body["options"]["num_ctx"] == 8192
    assert providers._cache_key("p", "ollama/m", system="a") != providers._cache_key("p", "ollama/m", system="b")


@pytest.mark.asyncio
async def test_connection_failure_is_recorded_as_failed_and_returns_none(records) -> None:
    with patch("httpx.AsyncClient", return_value=_client(httpx.ConnectError("no route"))):
        assert await providers._call_llm("p2", "ollama/m:latest") is None
    assert records[-1].outcome == "failed"


@pytest.mark.asyncio
async def test_exhausted_budget_is_recorded_and_no_request_is_sent(records) -> None:
    client = _client(OK)
    budget = AICallBudget(max_calls=1)
    budget.try_provider_attempt(None)
    with patch("httpx.AsyncClient", return_value=client):
        assert await providers._call_llm("p3", "ollama/m:latest", budget=budget) is None
    client.post.assert_not_called()
    assert records[-1].outcome == "over_budget"


@pytest.mark.asyncio
async def test_cache_hit_is_recorded_without_tokens(records) -> None:
    with patch("httpx.AsyncClient", return_value=_client(OK)):
        await providers._call_llm("p4", "ollama/m:latest")
        await providers._call_llm("p4", "ollama/m:latest")
    assert [record.outcome for record in records[-2:]] == ["ok", "cache_hit"]
    assert records[-1].prompt_tokens == 0


@pytest.mark.asyncio
async def test_deferred_records_carry_the_guard_decision_made_after_the_call(records) -> None:
    with patch("httpx.AsyncClient", return_value=_client(OK)):
        with call_audit.defer_ai_call_records() as deferred:
            await providers._call_llm("p5", "ollama/m:latest")
            assert records == []
            call_audit.mark_guard_rejected(deferred, "kev")
    assert records[-1].guard_rejected is True and records[-1].guard_reason == "kev"


def test_a_failing_sink_never_breaks_the_caller(records) -> None:
    def boom(_record) -> None:
        raise RuntimeError("audit store down")

    remove = call_audit.register_ai_call_sink(boom)
    try:
        call_audit.emit_ai_call(call_audit.AICallRecord(task="t", provider="p", model="m"))
    finally:
        remove()
    assert records


def test_scope_is_isolated_between_contexts() -> None:
    with call_audit.ai_call_scope(tenant_id="a", actor="x"):
        assert call_audit.current_scope() == ("a", "x")
    assert call_audit.current_scope() == ("", "")


@pytest.mark.asyncio
@pytest.mark.parametrize("task", list(EnrichmentTask))
async def test_planted_secrets_stop_at_the_provider_boundary_on_every_task(records, task, caplog) -> None:
    planted = ["ghp_" + "A" * 36, "AKIA" + "B" * 16, "postgres://u:p4ssw0rdvalue@db.internal/x", "api_key=" + "Zx9" * 8]
    client = _client(OK)
    with patch("httpx.AsyncClient", return_value=client):
        await providers._call_llm(f"{task.value} {' '.join(planted)}", "ollama/m:latest", task=task, system="rules")
    sent = json.dumps(client.post.call_args.kwargs["json"])
    audit_text = json.dumps(records[-1].to_details())
    for secret in planted:
        assert secret not in sent
        assert secret not in audit_text
        assert secret not in caplog.text


@pytest.mark.asyncio
async def test_structured_calls_are_gated_and_audited_like_every_other_call(records, monkeypatch) -> None:
    from pydantic import BaseModel

    class Answer(BaseModel):
        ok: bool

    client = _client(OK)
    with patch("httpx.AsyncClient", return_value=client):
        assert (await providers._call_llm_structured("structured prompt", "ollama/m:latest", Answer)) == Answer(ok=True)
    assert records[-1].outcome == "ok" and records[-1].provider == "ollama"
    monkeypatch.setattr(providers.provider_discovery, "OLLAMA_BASE_URL", "http://ollama.internal:11434")
    remote = _client(OK)
    with patch("httpx.AsyncClient", return_value=remote):
        assert await providers._call_llm_structured("other prompt", "ollama/m:latest", Answer) is None
    remote.post.assert_not_called()
    assert records[-1].outcome == "blocked"
