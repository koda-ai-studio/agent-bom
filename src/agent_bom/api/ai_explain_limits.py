"""Per-tenant rate and daily budget for on-demand explanation, shared across replicas where Postgres is."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from agent_bom.api.metrics import record_rate_limit_hit
from agent_bom.api.middleware_limits import _build_admission_rate_limit_store
from agent_bom.core.settings import env_int

_MINUTE_SECONDS = 60
_DAY_SECONDS = 86_400
DEFAULT_PER_MINUTE = 6
DEFAULT_PER_DAY = 200

_lock = threading.Lock()
_minute_store: Any = None
_day_store: Any = None


@dataclass(frozen=True, slots=True)
class ExplainDenied:
    message: str
    retry_after_seconds: int


def reset_explain_limits() -> None:
    global _minute_store, _day_store
    with _lock:
        _minute_store = _day_store = None


def _stores() -> tuple[Any, Any]:
    global _minute_store, _day_store
    with _lock:
        if _minute_store is None:
            _minute_store = _build_admission_rate_limit_store(_MINUTE_SECONDS)
        if _day_store is None:
            _day_store = _build_admission_rate_limit_store(_DAY_SECONDS)
        return _minute_store, _day_store


def consume_explain_allowance(tenant_id: str) -> ExplainDenied | None:
    """Take one call from the tenant's allowance, or say which limit stopped it."""
    per_minute = env_int("AGENT_BOM_AI_EXPLAIN_PER_MINUTE", DEFAULT_PER_MINUTE, minimum=1, on_invalid="default") or DEFAULT_PER_MINUTE
    per_day = env_int("AGENT_BOM_AI_EXPLAIN_PER_DAY", DEFAULT_PER_DAY, minimum=1, on_invalid="default") or DEFAULT_PER_DAY
    minute, day = _stores()
    now = time.time()
    allowed, _count, _reset = minute.consume_if_below(f"ai-explain:{tenant_id}", now, per_minute)
    if not allowed:
        record_rate_limit_hit("ai_explain")
        return ExplainDenied("Explain is rate limited for this tenant; try again shortly.", _MINUTE_SECONDS)
    allowed, _count, _reset = day.consume_if_below(f"ai-explain-day:{tenant_id}", now, per_day)
    if not allowed:
        record_rate_limit_hit("ai_explain_budget")
        return ExplainDenied("This tenant's daily AI explain budget is used up.", _DAY_SECONDS)
    return None
