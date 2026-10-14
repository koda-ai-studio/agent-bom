"""One canonical, metadata-only trace event that every trace source maps into.

Vendor payloads (Langfuse observations, LangSmith runs, OTLP spans and Snowflake
Cortex telemetry) are normalized here before anything reaches storage or the
graph. Raw prompt/output text never leaves the mapper: only a SHA-256 of it.
The tenant is always bound by the caller from the authenticated connection or
request scope; no vendor field can set it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from agent_bom.security import sanitize_path_label, sanitize_text

SOURCES = ("langfuse", "langsmith", "otel", "snowflake_cortex")
KINDS = ("agent", "llm", "tool", "retrieval", "mcp", "other")
SIGNALS = frozenset({"prompt_injection", "pii", "secret", "vulnerable_tool_call"})
MATCH_METHODS = ("exact", "candidate", "none")
STATUSES = ("ok", "error")
INVENTORY_NODE_KEY = "agent_bom.inventory_node_id"
AGENT_REF_KEY = "agent_bom.agent_ref"
CREDENTIAL_REF_KEY = "agent_bom.credential_ref"
NORMALIZED_ATTRIBUTE = "agent_bom.normalized"
_MAX_REFS = 20
_MAX_SPANS = 5000
_CREDENTIAL_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_PLAIN_REF = re.compile(r'^[A-Za-z0-9_$."/:-]{1,512}$')
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_LOCAL_PATH = re.compile(r"^(?:/|~|\.{1,2}[\\/]|\\|[A-Za-z]:[\\/])")


@dataclass(frozen=True)
class NormalizedTraceEvent:
    """``resource_refs`` is an ordered list and ``signals`` a set, held immutably."""

    tenant_id: str
    source: str
    source_trace_id: str
    source_span_id: str
    parent_span_id: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    kind: str = "other"
    agent_name: str | None = None
    agent_ref: str | None = None
    model_provider: str | None = None
    model_name: str | None = None
    tool_name: str | None = None
    mcp_server_ref: str | None = None
    resource_refs: tuple[str, ...] = ()
    principal_hash: str | None = None
    role_name: str | None = None
    credential_ref: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    status: str = "ok"
    signals: frozenset[str] = field(default_factory=frozenset)
    content_sha256: str | None = None
    match_method: str = "none"
    match_node_id: str | None = None

    def __post_init__(self) -> None:
        if self.source not in SOURCES or self.kind not in KINDS or self.status not in STATUSES:
            raise ValueError("Unsupported trace source, kind or status")
        if not self.source_span_id or not self.signals <= SIGNALS or self.match_method not in MATCH_METHODS:
            raise ValueError("Trace event requires a span identity and known signals")
        if (self.match_method == "none") != (self.match_node_id is None):
            raise ValueError("A matched trace event must name its node; an unmatched one must not")
        if self.credential_ref is not None and not _CREDENTIAL_NAME.match(self.credential_ref):
            raise ValueError("credential_ref must be a credential name, never a value")

    def bind_tenant(self, tenant_id: str) -> NormalizedTraceEvent:
        return replace(self, tenant_id=tenant_id)

    def to_dict(self) -> dict[str, Any]:
        payload = {item.name: getattr(self, item.name) for item in fields(self)}
        payload["resource_refs"] = list(self.resource_refs)
        payload["signals"] = sorted(self.signals)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> NormalizedTraceEvent:
        known = {item.name for item in fields(cls)}
        values = {key: value for key, value in payload.items() if key in known}
        values["resource_refs"] = tuple(str(ref) for ref in payload.get("resource_refs") or ())
        values["signals"] = frozenset(str(signal) for signal in payload.get("signals") or ())
        return cls(**values)


OPTIONAL_FIELDS = tuple(
    item.name
    for item in fields(NormalizedTraceEvent)
    if item.name not in {"tenant_id", "source", "source_span_id", "kind", "status", "signals", "match_method"}
)


def is_local_path(value: str) -> bool:
    return bool(_LOCAL_PATH.match(value)) or value.lower().startswith("file:")


def _text(value: object, max_len: int = 300) -> str | None:
    """Bounded, redacted label; a local filesystem path keeps only a ``<path:basename>`` label."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    return sanitize_path_label(text) if is_local_path(text) else sanitize_text(text, max_len=max_len) or None


def _identifier(value: object) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 512 and not is_local_path(value) else None


def _count(value: object) -> int | None:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**63 else None


def _cost(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return round(number, 8) if 0 <= number < 1e9 else None


def _timestamp(value: object, *, naive_utc: bool = False) -> str | None:
    """ISO-8601 UTC; a naive string is rejected unless the source documents it as UTC."""
    try:
        if isinstance(value, str) and not value.isdigit():
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if moment.tzinfo is None and naive_utc:
                moment = moment.replace(tzinfo=timezone.utc)
            return moment.astimezone(timezone.utc).isoformat() if moment.tzinfo else None
        nanos = int(value) if isinstance(value, (int, str)) and not isinstance(value, bool) else 0
        return (_EPOCH + timedelta(microseconds=nanos // 1000)).isoformat() if 0 < nanos < 2**64 else None
    except (ValueError, OverflowError):
        return None


PRINCIPAL_KEYED_PREFIX = "h1:"
PRINCIPAL_WEAK_PREFIX = "h1w:"
_PRINCIPAL_CONTEXT = b"agent-bom/trace-principal/v1\x00"
PrincipalDigest = Callable[[str], str]


def principal_digest(tenant_id: str, user_id: str, *, deployment_key: bytes | None) -> str:
    """Keyed, tenant-scoped digest of a user identifier; the raw identifier is never stored.

    ``tenant_key = HMAC-SHA256(deployment_key, context || tenant_id)`` and the
    digest is ``"h1:" + HMAC-SHA256(tenant_key, user_id)``. Without a deployment
    key the tenant key derives from the tenant id alone: still tenant-scoped,
    but dictionary-reversible by anyone who knows the tenant id, so it carries
    the ``"h1w:"`` prefix and coverage reports it as weak.
    """
    if not tenant_id or not user_id:
        raise ValueError("principal digest requires a tenant and a user identifier")
    context = _PRINCIPAL_CONTEXT + tenant_id.encode()
    tenant_key = hmac.new(deployment_key, context, hashlib.sha256).digest() if deployment_key else hashlib.sha256(context).digest()
    prefix = PRINCIPAL_KEYED_PREFIX if deployment_key else PRINCIPAL_WEAK_PREFIX
    return prefix + hmac.new(tenant_key, user_id.encode(), hashlib.sha256).hexdigest()


def is_weak_principal(value: str | None) -> bool:
    """True for a digest made without a deployment key (tenant-scoped but guessable)."""
    return bool(value and value.startswith(PRINCIPAL_WEAK_PREFIX))


def _principal(user_id: object, digest: PrincipalDigest | None) -> str | None:
    if digest is None or not isinstance(user_id, (str, int)) or isinstance(user_id, bool) or str(user_id) == "":
        return None
    return digest(str(user_id))


def content_sha256(*parts: object) -> str | None:
    if all(part in (None, "", [], {}) for part in parts):
        return None
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


def credential_name(value: object) -> str | None:
    return value if isinstance(value, str) and _CREDENTIAL_NAME.match(value) else None


def resource_ref(value: object) -> str | None:
    """A URL keeps scheme and host only; paths and queries may carry personal data."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if is_local_path(text):
        return None
    if "://" in text:
        parts = urlsplit(text)
        return f"{parts.scheme.lower()}://{parts.hostname}" if parts.scheme and parts.hostname else None
    return text if _PLAIN_REF.match(text) else None


def _retrieved_sources(output: object) -> list[str]:
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except ValueError:
            return []
    if isinstance(output, dict):
        output = output.get("documents") or output.get("output") or []
    refs: list[str] = []
    for document in output[:50] if isinstance(output, list) else []:
        if isinstance(document, dict):
            metadata = _dict(document.get("metadata"))
            ref = resource_ref(metadata.get("source") or document.get("source") or document.get("url"))
            if ref:
                refs.append(ref)
    return refs


def _refs(*values: object) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        for item in value if isinstance(value, list) else [value]:
            ref = resource_ref(item)
            if ref and ref not in refs:
                refs.append(ref)
    return tuple(refs[:_MAX_REFS])


def _match(kind: str, inventory_id: str | None, agent_ref: str | None) -> tuple[str, str | None]:
    node = inventory_id or (agent_ref if kind == "agent" else None)
    return ("exact", node) if node else ("none", None)


def _build(
    tenant_id: str, source: str, view: dict[str, Any], signals: frozenset[str], principal: PrincipalDigest | None
) -> NormalizedTraceEvent:
    kind = view["kind"]
    inventory_id = _identifier(view.get("inventory_id"))
    agent_ref = _identifier(view.get("agent_ref")) or (inventory_id if kind == "agent" else None)
    match_method, match_node_id = _match(kind, inventory_id, agent_ref)
    return NormalizedTraceEvent(
        tenant_id=tenant_id,
        source=source,
        source_trace_id=_identifier(view.get("trace_id")) or "",
        source_span_id=_identifier(view.get("span_id")) or "",
        parent_span_id=_identifier(view.get("parent_id")),
        started_at=_timestamp(view.get("started"), naive_utc=source == "langsmith"),
        ended_at=_timestamp(view.get("ended"), naive_utc=source == "langsmith"),
        kind=kind,
        agent_name=_text(view.get("agent_name")),
        agent_ref=agent_ref,
        model_provider=_text(view.get("provider"), 80),
        model_name=_text(view.get("model"), 200),
        tool_name=_text(view.get("tool")),
        mcp_server_ref=_identifier(view.get("server")),
        resource_refs=_refs(*view.get("resources", ())),
        principal_hash=_principal(view.get("user"), principal),
        role_name=_text(view.get("role"), 200),
        credential_ref=credential_name(view.get("credential")),
        input_tokens=_count(view.get("input_tokens")),
        output_tokens=_count(view.get("output_tokens")),
        cost_usd=_cost(view.get("cost")),
        status="error" if view.get("failed") else "ok",
        signals=signals & SIGNALS,
        content_sha256=content_sha256(*view.get("content", ())),
        match_method=match_method,
        match_node_id=match_node_id,
    )


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


_LANGFUSE_KINDS = {"AGENT": "agent", "GENERATION": "llm", "EMBEDDING": "llm", "TOOL": "tool", "RETRIEVER": "retrieval"}
_LANGSMITH_KINDS = {"llm": "llm", "embedding": "llm", "tool": "tool", "retriever": "retrieval"}


def from_langfuse_observation(
    row: Mapping[str, Any], *, tenant_id: str, signals: frozenset[str] = frozenset(), principal: PrincipalDigest | None = None
) -> NormalizedTraceEvent:
    metadata = _dict(row.get("metadata"))
    kind = _LANGFUSE_KINDS.get(str(row.get("type") or "").upper(), "mcp" if metadata.get("mcp.method.name") else "other")
    usage = _dict(row.get("usageDetails")) or _dict(row.get("usage"))
    costs = _dict(row.get("costDetails"))
    view = {
        "kind": kind,
        "trace_id": row.get("traceId"),
        "span_id": row.get("id"),
        "parent_id": row.get("parentObservationId"),
        "started": row.get("startTime"),
        "ended": row.get("endTime"),
        "agent_name": row.get("name") if kind == "agent" else metadata.get("agent_name"),
        "agent_ref": metadata.get(AGENT_REF_KEY),
        "inventory_id": metadata.get(INVENTORY_NODE_KEY),
        "provider": metadata.get("ls_provider") or metadata.get("gen_ai.provider.name") or metadata.get("provider"),
        "model": row.get("model"),
        "tool": row.get("name") if kind == "tool" else None,
        "server": metadata.get("mcp_server") or metadata.get("server"),
        "resources": (metadata.get("gen_ai.data_source.id"), metadata.get("data_source"), _retrieved_sources(row.get("output"))),
        "user": row.get("userId"),
        "role": metadata.get("role_name"),
        "credential": metadata.get(CREDENTIAL_REF_KEY),
        "input_tokens": usage.get("input"),
        "output_tokens": usage.get("output"),
        "cost": row.get("totalCost") if row.get("totalCost") is not None else costs.get("total"),
        "failed": str(row.get("level") or "").upper() == "ERROR",
        "content": (row.get("input"), row.get("output")),
    }
    return _build(tenant_id, "langfuse", view, signals, principal)


def from_langsmith_run(
    row: Mapping[str, Any], *, tenant_id: str, signals: frozenset[str] = frozenset(), principal: PrincipalDigest | None = None
) -> NormalizedTraceEvent:
    extra = _dict(row.get("extra"))
    metadata = _dict(extra.get("metadata"))
    run_type = str(row.get("run_type") or "").lower()
    agent_named = run_type == "chain" and (metadata.get("agent_name") or metadata.get(AGENT_REF_KEY))
    kind = "agent" if agent_named else _LANGSMITH_KINDS.get(run_type, "other")
    invocation = _dict(extra.get("invocation_params"))
    view = {
        "kind": kind,
        "trace_id": row.get("trace_id"),
        "span_id": row.get("id"),
        "parent_id": row.get("parent_run_id"),
        "started": row.get("start_time"),
        "ended": row.get("end_time"),
        "agent_name": metadata.get("agent_name") or (row.get("name") if kind == "agent" else None),
        "agent_ref": metadata.get(AGENT_REF_KEY),
        "inventory_id": metadata.get(INVENTORY_NODE_KEY),
        "provider": metadata.get("ls_provider"),
        "model": metadata.get("ls_model_name") or invocation.get("model") or invocation.get("model_name"),
        "tool": row.get("name") if kind == "tool" else None,
        "server": metadata.get("mcp_server") or metadata.get("server"),
        "resources": (metadata.get("data_source"), _retrieved_sources(row.get("outputs"))),
        "user": metadata.get("user_id"),
        "role": metadata.get("role_name"),
        "credential": metadata.get(CREDENTIAL_REF_KEY),
        "input_tokens": row.get("prompt_tokens"),
        "output_tokens": row.get("completion_tokens"),
        "cost": row.get("total_cost"),
        "failed": bool(row.get("error")) or row.get("status") == "error",
        "content": (row.get("inputs"), row.get("outputs")),
    }
    return _build(tenant_id, "langsmith", view, signals, principal)


_OTEL_OPERATIONS = {
    "invoke_agent": "agent",
    "create_agent": "agent",
    "chat": "llm",
    "text_completion": "llm",
    "generate_content": "llm",
    "embeddings": "llm",
    "execute_tool": "tool",
    "retrieval": "retrieval",
}


def otlp_attributes(raw: object) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for item in raw[:200] if isinstance(raw, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            continue
        value = _dict(item.get("value"))
        for kind in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if kind in value:
                values[item["key"]] = value[kind]
                break
    return values


def _otel_kind(name: str, attrs: Mapping[str, Any]) -> str:
    kind = _OTEL_OPERATIONS.get(str(attrs.get("gen_ai.operation.name") or ""))
    if kind:
        return kind
    if attrs.get("gen_ai.tool.name") or attrs.get("tool.name") or name.startswith("adk.tool."):
        return "tool"
    return "mcp" if attrs.get("mcp.method.name") else "other"


def from_otlp_span(
    span: Mapping[str, Any],
    *,
    tenant_id: str,
    resource_attributes: Mapping[str, Any] | None = None,
    signals: frozenset[str] = frozenset(),
    principal: PrincipalDigest | None = None,
) -> NormalizedTraceEvent:
    attrs = {**(resource_attributes or {}), **otlp_attributes(span.get("attributes"))}
    name = str(span.get("name") or "")
    kind = _otel_kind(name, attrs)
    view = {
        "kind": kind,
        "trace_id": span.get("traceId"),
        "span_id": span.get("spanId"),
        "parent_id": span.get("parentSpanId") or None,
        "started": span.get("startTimeUnixNano"),
        "ended": span.get("endTimeUnixNano"),
        "agent_name": attrs.get("gen_ai.agent.name"),
        "agent_ref": attrs.get(AGENT_REF_KEY),
        "inventory_id": attrs.get(INVENTORY_NODE_KEY),
        "provider": attrs.get("gen_ai.provider.name") or attrs.get("gen_ai.system"),
        "model": attrs.get("gen_ai.response.model") or attrs.get("gen_ai.request.model"),
        "tool": attrs.get("gen_ai.tool.name") or attrs.get("tool.name") or (name.removeprefix("adk.tool.") if kind == "tool" else None),
        "server": attrs.get("mcp.server"),
        "resources": (attrs.get("gen_ai.data_source.id"), attrs.get("mcp.resource.uri")),
        "user": attrs.get("user.id") or attrs.get("enduser.id"),
        "role": attrs.get("agent_bom.role_name"),
        "credential": attrs.get(CREDENTIAL_REF_KEY),
        "input_tokens": attrs.get("gen_ai.usage.input_tokens"),
        "output_tokens": attrs.get("gen_ai.usage.output_tokens"),
        "cost": attrs.get("agent_bom.cost_usd"),
        "failed": _dict(span.get("status")).get("code") == 2,
        "content": tuple(attrs.get(key) for key in ("gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.completion", "tool.output")),
    }
    return _build(tenant_id, "otel", view, signals, principal)


def iter_otlp_spans(body: Mapping[str, Any]) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Yield ``(span, resource attributes)`` from OTLP JSON or a flat span page."""
    emitted = 0
    for span in _list(body.get("spans")):
        if isinstance(span, dict) and emitted < _MAX_SPANS:
            emitted += 1
            yield span, {}
    for resource_span in _list(body.get("resourceSpans")):
        resource = otlp_attributes(_dict(_dict(resource_span).get("resource")).get("attributes"))
        for scope in _dict(resource_span).get("scopeSpans") or []:
            for span in _dict(scope).get("spans") or []:
                if isinstance(span, dict) and emitted < _MAX_SPANS:
                    emitted += 1
                    yield span, resource


def coverage_by_source(events: list[NormalizedTraceEvent]) -> dict[str, dict[str, Any]]:
    """How many events of each source supplied each optional canonical field."""
    coverage: dict[str, dict[str, Any]] = {}
    for event in events:
        entry = coverage.setdefault(event.source, {"events": 0, "supplied": dict.fromkeys(OPTIONAL_FIELDS, 0), "weak_principal_hashes": 0})
        entry["events"] += 1
        entry["weak_principal_hashes"] += is_weak_principal(event.principal_hash)
        for name in OPTIONAL_FIELDS:
            if getattr(event, name) not in (None, "", ()):
                entry["supplied"][name] += 1
    for entry in coverage.values():
        entry["missing"] = {name: entry["events"] - supplied for name, supplied in entry["supplied"].items()}
    return coverage
