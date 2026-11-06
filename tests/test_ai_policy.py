"""Off by default; a non-loopback provider takes an explicit opt-in."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.ai_components import ai_policy, provider_discovery, providers
from agent_bom.ai_enrich import _resolve_ai_provider


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AGENT_BOM_AI_ALLOW_REMOTE",
        "AGENT_BOM_AI_CONTROL_PLANE_ENABLED",
        "AGENT_BOM_AI_CONTROL_PLANE_TENANTS",
        "AGENT_BOM_AI_CONTROL_PLANE_MODEL",
        "LITELLM_PROXY_URL",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "OLLAMA_API_BASE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_control_plane_ai_is_off_by_default() -> None:
    decision = ai_policy.control_plane_decision("tenant-a")
    assert decision.enabled is False
    assert "AGENT_BOM_AI_CONTROL_PLANE_ENABLED" in decision.reason


def test_operator_setting_turns_it_on_and_an_allowlist_narrows_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_AI_CONTROL_PLANE_ENABLED", "1")
    assert ai_policy.control_plane_decision("tenant-a").enabled is True
    monkeypatch.setenv("AGENT_BOM_AI_CONTROL_PLANE_TENANTS", "tenant-b, tenant-c")
    assert ai_policy.control_plane_decision("tenant-a").enabled is False
    assert ai_policy.control_plane_decision("tenant-c").enabled is True


@pytest.mark.parametrize(
    ("model", "env", "local"),
    [
        ("ollama/llama3.2", {}, True),
        ("openai/gpt-4o-mini", {}, False),
        ("anthropic/claude", {}, False),
        ("huggingface/meta", {}, False),
        ("openai/local", {"OPENAI_API_BASE": "http://127.0.0.1:8000/v1"}, True),
        ("openai/remote", {"OPENAI_API_BASE": "https://api.example.com/v1"}, False),
        ("ollama_chat/llama3.2", {}, True),
        ("ollama_chat/llama3.2", {"OLLAMA_API_BASE": "http://10.0.0.9:11434"}, False),
        ("any/model", {"LITELLM_PROXY_URL": "http://localhost:4000"}, True),
        ("any/model", {"LITELLM_PROXY_URL": "https://llm.example.com"}, False),
    ],
)
def test_endpoint_locality(monkeypatch: pytest.MonkeyPatch, model: str, env: dict[str, str], local: bool) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert ai_policy.endpoint_is_local(model) is local


def test_non_loopback_ollama_is_remote() -> None:
    with patch.object(provider_discovery, "OLLAMA_BASE_URL", "http://ollama.internal:11434"):
        assert ai_policy.endpoint_is_local("ollama/llama3.2") is False


def test_remote_model_resolves_unavailable_without_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-value")
    with patch.object(provider_discovery, "_check_litellm", return_value=True):
        blocked = _resolve_ai_provider("openai/gpt-4.1-mini")
        monkeypatch.setenv("AGENT_BOM_AI_ALLOW_REMOTE", "1")
        allowed = _resolve_ai_provider("openai/gpt-4.1-mini")
    assert blocked.available is False
    assert blocked.status == "blocked"
    assert "AGENT_BOM_AI_ALLOW_REMOTE" in blocked.reason
    assert allowed.available is True


@pytest.mark.asyncio
async def test_a_direct_remote_call_is_refused_at_the_provider_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = SimpleNamespace(acompletion=AsyncMock(side_effect=AssertionError("must not be called")))
    with patch.dict(sys.modules, {"litellm": fake}):
        assert await providers._call_llm("hello", "openai/gpt-4.1-mini") is None
    fake.acompletion.assert_not_called()


def test_ollama_never_gains_a_remote_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_AI_ALLOW_REMOTE", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-value")
    with patch.object(provider_discovery, "_detect_ollama", return_value=False):
        resolution = _resolve_ai_provider("ollama/llama3.2")
    assert resolution.available is False
    assert resolution.provider is not None and resolution.provider.name == "ollama"


def test_keyless_litellm_ollama_chat_is_ready_only_on_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    assert provider_discovery._litellm_readiness("ollama_chat/llama3.2")[0] is True
    monkeypatch.setenv("OLLAMA_API_BASE", "http://10.0.0.9:11434")
    assert provider_discovery._litellm_readiness("ollama_chat/llama3.2")[0] is False


def test_operator_model_overrides_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    assert ai_policy.control_plane_model("openai/asked-for") == "openai/asked-for"
    monkeypatch.setenv("AGENT_BOM_AI_CONTROL_PLANE_MODEL", "ollama/llama3.2")
    assert ai_policy.control_plane_model("openai/asked-for") == "ollama/llama3.2"
