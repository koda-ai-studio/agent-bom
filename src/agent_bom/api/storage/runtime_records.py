"""Shared runtime record values and metadata-only serialization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from agent_bom.security import sanitize_sensitive_payload, sanitize_text

RAW_RUNTIME_FIELDS = {
    "args",
    "arguments",
    "input",
    "inputs",
    "output",
    "outputs",
    "prompt",
    "prompts",
    "raw",
    "raw_input",
    "raw_output",
    "raw_prompt",
    "request_body",
    "response_body",
    "tool_input",
    "tool_output",
    "tool_outputs",
}


@dataclass(frozen=True)
class RuntimeObservationRecord:
    tenant_id: str
    observation_id: str
    session_id: str
    observed_at: str
    source: str = "api"
    surface: str = "runtime"
    event_type: str = "runtime_event"
    severity: str = "unknown"
    verdict: str = "observed"
    tool_name: str = ""
    agent_name: str = ""
    trace_id: str = ""
    span_id: str = ""
    request_id: str = ""
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    redaction_status: str = "metadata_only"
    raw_payload_stored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeSessionRecord:
    tenant_id: str
    session_id: str
    first_seen: str
    last_seen: str
    source: str = "api"
    agent_name: str = ""
    trace_id: str = ""
    observation_count: int = 0
    event_types: dict[str, int] = field(default_factory=dict)
    verdicts: dict[str, int] = field(default_factory=dict)
    severities: dict[str, int] = field(default_factory=dict)
    tools: list[str] = field(default_factory=list)
    redaction_status: str = "metadata_only"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RuntimeMetadataCache:
    """Bounded redaction memoization owned by one import page, never a store."""

    def __init__(self) -> None:
        self.strings: dict[tuple[str | None, str, int], object] = {}
        self.keys: dict[str, str] = {}


def sanitize_runtime_metadata(value: object, *, max_items: int = 50, _cache: RuntimeMetadataCache | None = None) -> dict[str, Any]:
    """Return metadata safe for durable runtime observability storage.

    Raw prompt, argument, and tool-output fields are intentionally omitted.
    This preserves correlation and security verdicts without turning the
    observability store into a replay database.
    """
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for raw_key, raw_value in list(value.items())[:max_items]:
        key = sanitize_text(raw_key, max_len=120)
        if not key or key.lower() in RAW_RUNTIME_FIELDS:
            continue
        safe[key] = sanitize_sensitive_payload(
            raw_value,
            key=key,
            max_str_len=500,
            _string_cache=_cache.strings if _cache is not None else None,
            _key_cache=_cache.keys if _cache is not None else None,
        )
    return safe


def _observation_from_json(raw: str) -> RuntimeObservationRecord:
    payload = json.loads(raw)
    return RuntimeObservationRecord(
        tenant_id=str(payload["tenant_id"]),
        observation_id=str(payload["observation_id"]),
        session_id=str(payload["session_id"]),
        observed_at=str(payload["observed_at"]),
        source=str(payload.get("source") or "api"),
        surface=str(payload.get("surface") or "runtime"),
        event_type=str(payload.get("event_type") or "runtime_event"),
        severity=str(payload.get("severity") or "unknown"),
        verdict=str(payload.get("verdict") or "observed"),
        tool_name=str(payload.get("tool_name") or ""),
        agent_name=str(payload.get("agent_name") or ""),
        trace_id=str(payload.get("trace_id") or ""),
        span_id=str(payload.get("span_id") or ""),
        request_id=str(payload.get("request_id") or ""),
        summary=payload.get("summary") if isinstance(payload.get("summary"), dict) else {},
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
        redaction_status=str(payload.get("redaction_status") or "metadata_only"),
        raw_payload_stored=bool(payload.get("raw_payload_stored", False)),
    )


def _session_from_json(raw: str) -> RuntimeSessionRecord:
    payload = json.loads(raw)
    return RuntimeSessionRecord(
        tenant_id=str(payload["tenant_id"]),
        session_id=str(payload["session_id"]),
        first_seen=str(payload["first_seen"]),
        last_seen=str(payload["last_seen"]),
        source=str(payload.get("source") or "api"),
        agent_name=str(payload.get("agent_name") or ""),
        trace_id=str(payload.get("trace_id") or ""),
        observation_count=int(payload.get("observation_count") or 0),
        event_types={str(key): int(value) for key, value in (payload.get("event_types") or {}).items()},
        verdicts={str(key): int(value) for key, value in (payload.get("verdicts") or {}).items()},
        severities={str(key): int(value) for key, value in (payload.get("severities") or {}).items()},
        tools=[str(item) for item in payload.get("tools", []) if str(item)],
        redaction_status=str(payload.get("redaction_status") or "metadata_only"),
    )
