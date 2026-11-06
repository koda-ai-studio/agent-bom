"""Send AI call records to the tamper-evident audit chain and to Prometheus."""

from __future__ import annotations

import logging
import threading

from agent_bom.ai_components.call_audit import AICallRecord, register_ai_call_sink
from agent_bom.api.audit_log import log_action
from agent_bom.api.metrics import record_ai_call

_logger = logging.getLogger(__name__)
_registered = False
_lock = threading.Lock()


def _sink(record: AICallRecord) -> None:
    record_ai_call(task=record.task, provider=record.provider, outcome=record.outcome, latency_ms=record.latency_ms)
    details = record.to_details()
    actor = str(details.pop("actor") or "system")
    tenant_id = str(details.pop("tenant_id") or "default")
    log_action(
        "ai.call", actor=actor, resource=f"ai/{record.task}", tenant_id=tenant_id, **{f"ai_{key}": value for key, value in details.items()}
    )


def ensure_ai_call_sink() -> None:
    global _registered
    with _lock:
        if not _registered:
            register_ai_call_sink(_sink, required=True)
            _registered = True
