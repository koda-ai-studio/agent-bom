"""Shared enrichment request state, budgets and bounded retries."""

from __future__ import annotations

import asyncio
import logging
import random
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable, Optional, TypeVar

import httpx
from rich.console import Console

from agent_bom import config
from agent_bom.ai_components.ai_prompts import redact_secrets as redact_secrets
from agent_bom.config import AI_CACHE_MAX_ENTRIES as _MAX_AI_CACHE
from agent_bom.security import sanitize_error

console = Console(stderr=True)


logger = logging.getLogger("agent_bom.ai_enrich")


_cache: dict[str, str] = {}


_cache_lock = threading.RLock()


def _response_text(value: object) -> str:
    """Return stripped provider text only when the provider returned a string."""
    return value.strip() if isinstance(value, str) else ""


def _ai_cache_get(key: str) -> str | None:
    """Read a cached AI response with synchronization."""
    with _cache_lock:
        return _cache.get(key)


def _ai_cache_put(key: str, value: str) -> None:
    """Insert into bounded AI response cache."""
    with _cache_lock:
        _cache[key] = value
        if len(_cache) > _MAX_AI_CACHE:
            for k in list(_cache.keys())[: len(_cache) - _MAX_AI_CACHE]:
                del _cache[k]


DEFAULT_MODEL = "openai/gpt-4o-mini"


OLLAMA_DEFAULT_MODEL = "llama3.2"


HF_DEFAULT_MODEL = "meta-llama/Llama-3.1-8B-Instruct"


AI_PROMPT_VERSION = "ai-enrichment.v2"


OLLAMA_MODEL_PREFERENCE = [
    "llama3.1:8b",
    "llama3.2",
    "llama3.2:3b",
    "qwen2.5:7b",
    "glm4:9b",
    "glm4",
    "mistral:7b",
    "mistral",
    "gemma2:9b",
    "phi3:medium",
]


def _prepare_prompt(prompt: str) -> str:
    """Apply redaction to an outbound prompt when enabled by config."""
    if getattr(config, "AI_REDACT_PROMPTS", True):
        return redact_secrets(prompt)
    return prompt


def _effective_temperature() -> float:
    """Temperature for a call: 0.0 in deterministic mode, else configured."""
    deterministic = _AI_DETERMINISTIC_OVERRIDE.get()
    if deterministic is None:
        deterministic = bool(getattr(config, "AI_DETERMINISTIC", False))
    if deterministic:
        return 0.0
    return float(getattr(config, "AI_TEMPERATURE", 0.3))


_AI_DETERMINISTIC_OVERRIDE: ContextVar[bool | None] = ContextVar("ai_deterministic_override", default=None)


_AI_RUN_ID: ContextVar[str | None] = ContextVar("ai_run_id", default=None)


def _request_timeout() -> float:
    return float(getattr(config, "AI_REQUEST_TIMEOUT", 120.0))


_T = TypeVar("_T")


_RETRYABLE_EXC = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)


async def retry_async(
    func: Callable[[], Awaitable[Optional[_T]]],
    *,
    max_retries: int | None = None,
    base_delay: float | None = None,
    max_delay: float | None = None,
    retry_on: tuple[type[BaseException], ...] = _RETRYABLE_EXC,
    label: str = "llm-call",
) -> Optional[_T]:
    """Call *func* with bounded exponential backoff + jitter.

    Returns the first non-None result. On a retryable exception it backs off and
    retries; once retries are exhausted (or a non-retryable exception fires) it
    returns None so the enrichment layer degrades gracefully rather than raising.
    """
    attempts = (max_retries if max_retries is not None else getattr(config, "AI_MAX_RETRIES", 2)) + 1
    base = base_delay if base_delay is not None else getattr(config, "AI_RETRY_BASE_DELAY", 0.5)
    ceiling = max_delay if max_delay is not None else getattr(config, "AI_RETRY_MAX_DELAY", 8.0)

    for attempt in range(attempts):
        try:
            result = await func()
        except retry_on as exc:
            if attempt >= attempts - 1:
                logger.warning("%s failed after %d attempt(s): %s", label, attempt + 1, sanitize_error(str(exc), generic=True))
                return None
            delay = min(base * (2**attempt), ceiling) + random.uniform(0, base)
            logger.debug(
                "%s retry %d/%d after %.2fs (%s)",
                label,
                attempt + 1,
                attempts - 1,
                delay,
                sanitize_error(str(exc), generic=True),
            )
            await asyncio.sleep(delay)
            continue
        except Exception as exc:  # non-retryable — degrade, don't raise
            logger.warning("%s failed (non-retryable): %s", label, sanitize_error(exc, generic=True))
            return None
        if result is not None:
            return result
        return None
    return None


class EnrichmentTask(str, Enum):
    """Kinds of enrichment work, used to pick a per-task model + provenance."""

    NARRATIVE = "narrative"  # blast-radius risk narratives
    SUMMARY = "summary"  # executive summaries
    TAGGING = "tagging"  # compliance / control classification (cheap)
    DETECTION = "detection"  # LLM-assisted novel-issue detection (strong)
    TRIAGE = "triage"  # FP reduction / dedup (strong)
    CONFIG_ANALYSIS = "config_analysis"  # MCP config security review


@dataclass
class AICallBudget:
    """Run-wide cap and accounting for actual provider requests."""

    max_calls: int = 50
    provider_attempts: int = 0
    cache_hits: int = 0
    retries: int = 0
    attempts_by_task: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if self.max_calls < 0:
            raise ValueError("AI provider-attempt budget must be non-negative")

    def try_provider_attempt(self, task: EnrichmentTask | None, *, retry: bool = False) -> bool:
        """Reserve one provider request before any network/provider call."""
        task_name = task.value if task is not None else "unspecified"
        with self._lock:
            if self.max_calls > 0 and self.provider_attempts >= self.max_calls:
                return False
            self.provider_attempts += 1
            if retry:
                self.retries += 1
            self.attempts_by_task[task_name] = self.attempts_by_task.get(task_name, 0) + 1
            return True

    def record_cache_hit(self) -> None:
        with self._lock:
            self.cache_hits += 1

    def to_dict(self) -> dict[str, object]:
        with self._lock:
            remaining = None if self.max_calls == 0 else max(self.max_calls - self.provider_attempts, 0)
            return {
                "max_provider_attempts": self.max_calls,
                "provider_attempts": self.provider_attempts,
                "provider_attempts_remaining": remaining,
                "cache_hits": self.cache_hits,
                "retries": self.retries,
                "exhausted": self.max_calls > 0 and self.provider_attempts >= self.max_calls,
                "attempts_by_task": dict(sorted(self.attempts_by_task.items())),
            }


_TASK_TIER: dict[EnrichmentTask, str] = {
    EnrichmentTask.NARRATIVE: "cheap",
    EnrichmentTask.SUMMARY: "cheap",
    EnrichmentTask.TAGGING: "cheap",
    EnrichmentTask.DETECTION: "strong",
    EnrichmentTask.TRIAGE: "strong",
    EnrichmentTask.CONFIG_ANALYSIS: "strong",
}


def resolve_task_model(task: EnrichmentTask, default_model: str = DEFAULT_MODEL) -> str:
    """Resolve the model to use for *task*.

    Precedence: an explicitly-configured per-tier model (cheap/strong) wins;
    otherwise fall back to *default_model* (which itself auto-detects Ollama /
    HF / litellm via :func:`_resolve_ai_provider`).
    """
    tier = _TASK_TIER.get(task, "strong")
    configured = getattr(config, "AI_MODEL_STRONG" if tier == "strong" else "AI_MODEL_CHEAP", "")
    if configured:
        return configured
    return default_model
