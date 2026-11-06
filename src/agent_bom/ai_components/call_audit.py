"""One record per model call: who, what, how long, and what the guards did. Never prompt text.

This layer cannot import the control plane, so sinks register themselves: the API
writes to the tamper-evident audit chain and to Prometheus; every process logs.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from functools import partial
from typing import TypeVar

import httpx

logger = logging.getLogger("agent_bom.ai_enrich")
_T = TypeVar("_T")

OUTCOMES = frozenset({"ok", "empty", "failed", "blocked", "over_budget", "over_capacity", "cache_hit"})
_DIGEST_TTL_SECONDS = 300.0


@dataclass(slots=True)
class AICallRecord:
    task: str
    provider: str
    model: str
    tenant_id: str = ""
    actor: str = ""
    model_digest: str = ""
    prompt_sha256: str = ""
    response_sha256: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    outcome: str = "failed"
    guard_rejected: bool = False
    guard_reason: str = ""

    def to_details(self) -> dict[str, object]:
        details = asdict(self)
        details["latency_ms"] = round(self.latency_ms, 1)
        return details


class AICallAuditError(RuntimeError):
    """A required audit write failed, so this call's output must not be used."""


_scope: ContextVar[tuple[str, str]] = ContextVar("ai_call_scope", default=("", ""))
_audit_required: ContextVar[bool] = ContextVar("ai_call_audit_required", default=False)
_deferred: ContextVar[list[AICallRecord] | None] = ContextVar("ai_call_deferred", default=None)
_active: ContextVar[AICallRecord | None] = ContextVar("ai_call_active", default=None)
_sinks: list[tuple[Callable[[AICallRecord], None], bool]] = []
_sinks_lock = threading.Lock()
_digests: dict[tuple[str, str], tuple[float, str]] = {}


def register_ai_call_sink(sink: Callable[[AICallRecord], None], *, required: bool = False) -> Callable[[], None]:
    """A required sink is the record of the call: a scope that demands it loses the output if the sink fails."""
    entry = (sink, required)
    with _sinks_lock:
        _sinks.append(entry)

    def remove() -> None:
        with _sinks_lock:
            if entry in _sinks:
                _sinks.remove(entry)

    return remove


@contextmanager
def ai_call_scope(*, tenant_id: str, actor: str, audit_required: bool = False) -> Iterator[None]:
    token = _scope.set((tenant_id, actor))
    required = _audit_required.set(audit_required)
    try:
        yield
    finally:
        _audit_required.reset(required)
        _scope.reset(token)


def current_scope() -> tuple[str, str]:
    return _scope.get()


def best_effort(operation: Callable[[], _T], label: str) -> _T | None:
    """Optional AI bookkeeping: pluggable stores raise driver errors, and none may reach a scan or a read."""
    try:
        return operation()
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s skipped: %s", label, type(exc).__name__)
        return None


def _deliver(sink: Callable[[AICallRecord], None], record: AICallRecord) -> bool:
    sink(record)
    return True


def emit_ai_call(record: AICallRecord) -> None:
    """A broken sink must not change the outcome of a scan or a read."""
    logger.info(
        "ai_call task=%s provider=%s model=%s outcome=%s latency_ms=%.1f tokens=%d/%d guard_rejected=%s",
        record.task,
        record.provider,
        record.model,
        record.outcome,
        record.latency_ms,
        record.prompt_tokens,
        record.completion_tokens,
        record.guard_rejected,
    )
    with _sinks_lock:
        sinks = list(_sinks)
    delivered = True
    for sink, required in sinks:
        ok = best_effort(partial(_deliver, sink, record), "AI call audit sink")
        delivered = delivered and (bool(ok) or not required)
    if not delivered and _audit_required.get():
        raise AICallAuditError("the audit record for this AI call could not be written")


@contextmanager
def defer_ai_call_records() -> Iterator[list[AICallRecord]]:
    """Hold records until the caller has run its guards over the response."""
    records: list[AICallRecord] = []
    token = _deferred.set(records)
    try:
        yield records
    finally:
        _deferred.reset(token)
        for record in records:
            emit_ai_call(record)


def mark_guard_rejected(records: list[AICallRecord], reason: str) -> None:
    for record in records:
        record.guard_rejected = True
        record.guard_reason = reason[:64]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@contextmanager
def observe_ai_call(*, task: str, provider: str, model: str, prompt_sha256: str) -> Iterator[AICallRecord]:
    tenant_id, actor = _scope.get()
    record = AICallRecord(task=task, provider=provider, model=model, tenant_id=tenant_id, actor=actor, prompt_sha256=prompt_sha256)
    token = _active.set(record)
    started = time.perf_counter()
    try:
        yield record
    finally:
        _active.reset(token)
        record.latency_ms = (time.perf_counter() - started) * 1000
        deferred = _deferred.get()
        if deferred is None:
            emit_ai_call(record)
        else:
            deferred.append(record)


def note_outcome(outcome: str) -> None:
    record = _active.get()
    if record is not None:
        record.outcome = outcome


def note_usage(*, prompt_tokens: object = 0, completion_tokens: object = 0, digest: str = "") -> None:
    record = _active.get()
    if record is None:
        return
    record.prompt_tokens = prompt_tokens if isinstance(prompt_tokens, int) else 0
    record.completion_tokens = completion_tokens if isinstance(completion_tokens, int) else 0
    if digest:
        record.model_digest = digest


def reset_digest_cache() -> None:
    _digests.clear()


async def ollama_model_digest(client: httpx.AsyncClient, base_url: str, model: str) -> str:
    """The exact weights behind a tag; a tag alone can move between runs."""
    now = time.monotonic()
    cached = _digests.get((base_url, model))
    if cached is not None and now - cached[0] < _DIGEST_TTL_SECONDS:
        return cached[1]
    digest = ""
    try:
        response = await client.get(f"{base_url}/api/tags")
        if response.status_code == 200:
            for entry in response.json().get("models", []):
                if entry.get("name") == model or entry.get("name") == f"{model}:latest":
                    digest = str(entry.get("digest") or "")[:128]
                    break
    except (httpx.HTTPError, ValueError, AttributeError):
        digest = ""
    _digests[(base_url, model)] = (now, digest)
    return digest
