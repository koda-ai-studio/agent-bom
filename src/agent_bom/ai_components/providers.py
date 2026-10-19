"""Provider adapters and structured generation calls."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import TYPE_CHECKING, Optional

import httpx

from agent_bom import config
from agent_bom.ai_components import provider_discovery
from agent_bom.config import OLLAMA_BASE_URL
from agent_bom.core.settings import env_is_set, env_opt
from agent_bom.security import sanitize_error

if TYPE_CHECKING:
    from pydantic import BaseModel

from agent_bom.ai_components.call_state import (
    _AI_RUN_ID,
    AI_PROMPT_VERSION,
    HF_DEFAULT_MODEL,
    AICallBudget,
    EnrichmentTask,
    _ai_cache_get,
    _ai_cache_put,
    _effective_temperature,
    _prepare_prompt,
    _request_timeout,
    _response_text,
    logger,
    retry_async,
)
from agent_bom.ai_components.provider_discovery import (
    AI_PROVIDER_DESCRIPTORS,
    AIProviderDescriptor,
    _provider_name_for_model,
)


class EnrichmentProvider:
    """Uniform provider contract for the enrichment harness.

    Subclasses expose availability + a single ``generate`` coroutine. Redaction,
    caching, retries and timeouts are handled inside the wrapped ``_call_*``
    functions, so adapters stay thin.
    """

    descriptor: AIProviderDescriptor

    def is_available(self) -> bool:  # pragma: no cover - trivial
        raise NotImplementedError

    async def generate(self, prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:  # pragma: no cover
        raise NotImplementedError

    @property
    def name(self) -> str:
        return self.descriptor.name


class OllamaProvider(EnrichmentProvider):
    descriptor = AI_PROVIDER_DESCRIPTORS["ollama"]

    def is_available(self) -> bool:
        return provider_discovery._detect_ollama()

    async def generate(self, prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
        bare = model[len("ollama/") :] if model.startswith("ollama/") else model
        return await _call_ollama_direct(prompt, bare, max_tokens)


class HuggingFaceProvider(EnrichmentProvider):
    descriptor = AI_PROVIDER_DESCRIPTORS["huggingface"]

    def is_available(self) -> bool:
        return provider_discovery._check_huggingface() and env_is_set("HF_TOKEN")

    async def generate(self, prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
        hf_model = model[len("huggingface/") :] if model.startswith("huggingface/") else model
        return await _call_huggingface(prompt, model=hf_model or HF_DEFAULT_MODEL, max_tokens=max_tokens)


class LiteLLMProvider(EnrichmentProvider):
    descriptor = AI_PROVIDER_DESCRIPTORS["litellm"]

    def is_available(self) -> bool:
        return provider_discovery._check_litellm()

    async def generate(self, prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
        return await _call_llm_via_litellm(prompt, model, max_tokens)


PROVIDER_REGISTRY: dict[str, EnrichmentProvider] = {
    "ollama": OllamaProvider(),
    "huggingface": HuggingFaceProvider(),
    "litellm": LiteLLMProvider(),
}


def get_provider(name: str) -> EnrichmentProvider:
    """Return the registered provider adapter by name (KeyError if unknown)."""
    return PROVIDER_REGISTRY[name]


def provider_for_model(model: str) -> EnrichmentProvider:
    """Return the provider adapter that owns *model* by its prefix."""
    return PROVIDER_REGISTRY[_provider_name_for_model(model)]


def _cache_key(
    prompt: str,
    model: str,
    *,
    task: EnrichmentTask | None = None,
    provider: str | None = None,
) -> str:
    """Hash every execution posture field that can change model output."""
    prepared_prompt = _prepare_prompt(prompt)
    posture = {
        # The cache is process-global for bounded memory reuse, but responses
        # are evidence belonging to one enrichment run. Run scoping prevents a
        # concurrent tenant/scan from reusing and relabeling another run's
        # response while preserving deduplication within the run.
        "run_id": _AI_RUN_ID.get() or "standalone",
        "provider": provider or _provider_name_for_model(model),
        "model": model,
        "model_revision": str(getattr(config, "AI_MODEL_REVISION", "") or ""),
        "task": task.value if task is not None else "unspecified",
        "temperature": _effective_temperature(),
        "redaction": bool(getattr(config, "AI_REDACT_PROMPTS", True)),
        "prompt_version": AI_PROMPT_VERSION,
        "prompt": prepared_prompt,
    }
    encoded = json.dumps(posture, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


async def _call_ollama_direct(
    prompt: str,
    model: str,
    max_tokens: int = 500,
    *,
    task: EnrichmentTask | None = None,
    budget: AICallBudget | None = None,
) -> Optional[str]:
    """Call Ollama directly via HTTP API (no litellm dependency needed).

    The *model* parameter is the bare model name (e.g. ``llama3.2``).
    """
    full_model = f"ollama/{model}"
    key = _cache_key(prompt, full_model, task=task, provider="ollama")
    cached = _ai_cache_get(key)
    if cached is not None:
        if budget is not None:
            budget.record_cache_hit()
        return cached

    outbound = _prepare_prompt(prompt)
    if budget is not None and not budget.try_provider_attempt(task):
        return None
    try:
        async with httpx.AsyncClient(timeout=_request_timeout()) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": outbound}],
                    "stream": False,
                    "options": {
                        "num_predict": max_tokens,
                        "temperature": _effective_temperature(),
                    },
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                message = data.get("message", {})
                content = message.get("content") if isinstance(message, dict) else None
                text = _response_text(content)
                if text:
                    _ai_cache_put(key, text)
                    return text
            logger.warning("Ollama returned status %d", resp.status_code)
            return None
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        logger.warning("Ollama connection failed: %s", sanitize_error(exc, generic=True))
        return None
    except Exception as exc:
        logger.warning("Ollama call failed: %s", sanitize_error(exc, generic=True))
        return None


async def _call_llm_via_litellm(
    prompt: str,
    model: str,
    max_tokens: int = 500,
    *,
    task: EnrichmentTask | None = None,
    budget: AICallBudget | None = None,
) -> Optional[str]:
    """Call LLM via litellm with caching and error handling."""
    key = _cache_key(prompt, model, task=task, provider="litellm")
    cached = _ai_cache_get(key)
    if cached is not None:
        if budget is not None:
            budget.record_cache_hit()
        return cached

    outbound = _prepare_prompt(prompt)
    attempt_index = 0

    async def _once() -> Optional[str]:
        nonlocal attempt_index
        is_retry = attempt_index > 0
        if budget is not None and not budget.try_provider_attempt(task, retry=is_retry):
            return None
        attempt_index += 1
        try:
            from litellm import acompletion
        except ImportError:
            logger.warning("litellm not installed. Install with: pip install 'agent-bom[ai-enrich]'")
            return None
        response = await acompletion(
            model=model,
            messages=[{"role": "user", "content": outbound}],
            max_tokens=max_tokens,
            temperature=_effective_temperature(),
            timeout=_request_timeout(),
        )
        text = _response_text(response.choices[0].message.content)
        return text or None

    text = await retry_async(_once, retry_on=(Exception,), label=f"litellm:{model}")
    if text:
        _ai_cache_put(key, text)
    return text


async def _call_huggingface(
    prompt: str,
    model: str = HF_DEFAULT_MODEL,
    max_tokens: int = 500,
    *,
    task: EnrichmentTask | None = None,
    budget: AICallBudget | None = None,
) -> Optional[str]:
    """Call HuggingFace Inference API (free tier available).

    Uses ``huggingface_hub.InferenceClient.chat_completion()``.
    Requires ``HF_TOKEN`` env var for gated models.
    """
    full_model = f"huggingface/{model}"
    key = _cache_key(prompt, full_model, task=task, provider="huggingface")
    cached = _ai_cache_get(key)
    if cached is not None:
        if budget is not None:
            budget.record_cache_hit()
        return cached

    outbound = _prepare_prompt(prompt)
    attempt_index = 0

    async def _once() -> Optional[str]:
        nonlocal attempt_index
        is_retry = attempt_index > 0
        if budget is not None and not budget.try_provider_attempt(task, retry=is_retry):
            return None
        attempt_index += 1
        try:
            from huggingface_hub import InferenceClient
        except ImportError:
            logger.warning("huggingface-hub not installed. Install with: pip install 'agent-bom[huggingface]'")
            return None
        client = InferenceClient(model=model, token=env_opt("HF_TOKEN"))
        # Run sync client in executor to avoid blocking event loop
        response = await asyncio.to_thread(
            client.chat_completion,
            messages=[{"role": "user", "content": outbound}],
            max_tokens=max_tokens,
            temperature=_effective_temperature(),
        )
        return _response_text(response.choices[0].message.content) or None

    text = await retry_async(_once, retry_on=(Exception,), label=f"huggingface:{model}")
    if text:
        _ai_cache_put(key, text)
    return text


async def _call_llm(
    prompt: str,
    model: str,
    max_tokens: int = 500,
    *,
    task: EnrichmentTask | None = None,
    budget: AICallBudget | None = None,
) -> Optional[str]:
    """Call LLM via the best available provider.

    Provider prefixes are strict data-boundary decisions. In particular, an
    explicit ``ollama/*`` model never falls back to a remote provider.
    """
    if model.startswith("ollama/"):
        bare_model = model[len("ollama/") :]
        return await _call_ollama_direct(prompt, bare_model, max_tokens, task=task, budget=budget)

    if model.startswith("huggingface/"):
        hf_model = model[len("huggingface/") :]
        return await _call_huggingface(prompt, model=hf_model, max_tokens=max_tokens, task=task, budget=budget)

    return await _call_llm_via_litellm(prompt, model, max_tokens, task=task, budget=budget)


def _parse_json_response(response: str) -> dict | None:
    """Parse a JSON response with 3 fallback strategies.

    1. Clean JSON
    2. Markdown-fenced JSON (```json ... ```)
    3. Brace-extraction from text

    Returns None for non-parseable responses.
    """
    if not response or not response.strip():
        return None

    text = response.strip()

    # Attempt 1: Parse as clean JSON directly
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Attempt 2: Extract from markdown fencing
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
    if fence_match:
        try:
            data = json.loads(fence_match.group(1))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    # Attempt 3: Find JSON object embedded in other text
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        try:
            data = json.loads(brace_match.group(0))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    return None


async def _call_ollama_structured(
    prompt: str,
    model: str,
    schema_cls: type[BaseModel],
    max_tokens: int = 500,
) -> Optional[BaseModel]:
    """Call Ollama with structured output via the ``format`` parameter.

    Passes the Pydantic schema's JSON schema to force valid JSON output.
    Falls back to None on error.
    """
    key = _cache_key(prompt, f"ollama/{model}:structured")
    cached = _ai_cache_get(key)
    if cached is not None:
        try:
            return schema_cls.model_validate_json(cached)
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass

    try:
        json_schema = schema_cls.model_json_schema()
        outbound = _prepare_prompt(prompt)
        async with httpx.AsyncClient(timeout=_request_timeout()) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": outbound}],
                    "stream": False,
                    "format": json_schema,
                    "options": {
                        "num_predict": max_tokens,
                        "temperature": _effective_temperature(),
                    },
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data.get("message", {}).get("content", "").strip()
                if text:
                    _ai_cache_put(key, text)
                    return schema_cls.model_validate_json(text)
        return None
    except Exception as exc:
        logger.debug(
            "Structured Ollama call failed: %s, falling back to unstructured",
            sanitize_error(exc, generic=True),
        )
        return None


async def _call_llm_structured(
    prompt: str,
    model: str,
    schema_cls: type[BaseModel],
    max_tokens: int = 500,
) -> Optional[BaseModel]:
    """Call LLM with structured output, falling back to unstructured + parse.

    Routing:
    1. ollama/* → ``_call_ollama_structured`` (native ``format`` param)
    2. Fallback: unstructured call + ``schema.model_validate_json()``
    """
    if model.startswith("ollama/"):
        bare_model = model[len("ollama/") :]
        result = await _call_ollama_structured(prompt, bare_model, schema_cls, max_tokens)
        if result is not None:
            return result

    # Fallback: unstructured call + parse
    raw = await _call_llm(prompt, model, max_tokens)
    if raw:
        # Try direct JSON parse
        try:
            return schema_cls.model_validate_json(raw)
        except (json.JSONDecodeError, ValueError):
            pass
        # Try extracting from markdown/braces
        parsed = _parse_json_response(raw)
        if parsed:
            try:
                return schema_cls.model_validate(parsed)
            except (ValueError, TypeError):
                pass
    return None
