"""OCSF normalization and runtime observation persistence."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, cast

from fastapi import Request

from agent_bom.api.ocsf_fields import _ocsf_finding_message, _resource_name, ocsf_identity_context
from agent_bom.api.runtime_event_store import RuntimeObservationRecord, get_runtime_event_store, sanitize_runtime_metadata
from agent_bom.api.storage.runtime_records import RuntimeMetadataCache
from agent_bom.api.stores import _get_analytics_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.canonical_ids import canonical_id
from agent_bom.core.severity import ocsf_to_severity
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_text

_logger = logging.getLogger("agent_bom.api.routes.observability")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _extract_ocsf_events(body: dict | list[dict]) -> list[dict]:
    if isinstance(body, list):
        events = body
    elif isinstance(body, dict):
        if isinstance(body.get("events"), list):
            events = body["events"]
        elif "class_uid" in body or "class_name" in body:
            events = [body]
        else:
            raise ValueError("OCSF ingest expects a single event, a list of events, or an object with an 'events' array")
    else:
        raise ValueError("OCSF ingest payload must be an object or array")

    normalized_events = [event for event in events if isinstance(event, dict)]
    if len(normalized_events) != len(events):
        raise ValueError("OCSF ingest events must be JSON objects")
    return normalized_events


def _slug(value: str) -> str:
    return "_".join(part for part in value.lower().replace("/", " ").replace("-", " ").split() if part)


def _ocsf_timestamp(value: object) -> str:
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1_000_000_000_000:
            seconds /= 1000.0
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    if isinstance(value, str) and value.strip().isdigit():
        return _ocsf_timestamp(int(value.strip()))
    if isinstance(value, str) and value.strip():
        return value.strip()
    return _now()


def _ocsf_finding_detector(event: dict) -> str:
    finding_info = event.get("finding_info")
    if isinstance(finding_info, dict):
        analytic = finding_info.get("analytic")
        if isinstance(analytic, dict):
            for key in ("uid", "name", "type"):
                candidate = str(analytic.get(key, "")).strip()
                if candidate:
                    return candidate
        types = finding_info.get("types")
        if isinstance(types, list):
            for item in types:
                candidate = str(item).strip()
                if candidate:
                    return candidate
        if uid := str(finding_info.get("uid", "")).strip():
            return uid
    return _slug(str(event.get("class_name", "ocsf_event")).strip() or "ocsf_event")


def _normalize_ocsf_event(event: dict, *, tenant_id: str) -> dict:
    class_name = str(event.get("class_name", "")).strip() or "OCSF Event"
    class_uid = event.get("class_uid")
    class_slug = _slug(class_name) or "ocsf_event"
    source_meta = event.get("metadata")
    metadata_uid = ""
    source_id = ""
    if isinstance(source_meta, dict):
        product = source_meta.get("product")
        if isinstance(product, dict):
            source_id = str(product.get("name", "")).strip()
            if not source_id:
                source_id = str(product.get("vendor_name", "")).strip()
        if not source_id:
            source_id = str(source_meta.get("log_name", "")).strip()
        metadata_uid = str(source_meta.get("uid", "")).strip()
    event_id = ""
    finding_info = event.get("finding_info")
    if isinstance(finding_info, dict):
        event_id = str(finding_info.get("uid", "")).strip()
    if not event_id:
        event_id = metadata_uid
    severity = str(event.get("severity", "")).strip().lower()
    if not severity:
        try:
            severity = ocsf_to_severity(int(event.get("severity_id", 0)))
        except Exception:
            severity = "unknown"
    reported_time = event.get("time") or event.get("start_time") or event.get("event_time")
    event_timestamp = _ocsf_timestamp(reported_time)
    detector = _ocsf_finding_detector(event)
    tool_name = _resource_name(event)
    message = _ocsf_finding_message(event)
    if not event_id:
        # Deterministic content-derived ID so retries of an id-less OCSF event
        # collapse on the runtime observation PK (tenant_id, observation_id)
        # instead of leaking a fresh uuid4 per ingest (audit item J).
        event_id = canonical_id(
            "ocsf_event",
            tenant_id,
            source_id,
            event_timestamp if reported_time else "",
            class_uid,
            class_name,
            detector,
            tool_name,
            message,
        )
    normalized = {
        "event_id": event_id,
        "event_timestamp": event_timestamp,
        "timestamp_basis": "reported" if reported_time else "receipt",
        "tenant_id": tenant_id,
        "event_type": f"ocsf_{class_slug}",
        "detector": detector,
        "severity": severity or "unknown",
        "tool_name": tool_name,
        "message": message,
        "agent_name": "",
        "session_id": "",
        "trace_id": "",
        "request_id": "",
        "source_id": source_id,
        "ocsf_class_uid": class_uid,
        "ocsf_class_name": class_name,
    }
    observables = event.get("observables")
    if isinstance(observables, list):
        for observable in observables:
            if isinstance(observable, dict):
                trace_id = str(observable.get("trace_id", "")).strip()
                if trace_id:
                    normalized["trace_id"] = trace_id
                    break
    normalized.update(ocsf_identity_context(event, tenant_id=tenant_id, source_id=source_id, event_id=event_id))
    return normalized


def _bounded(value: object, *, max_len: int = 200, _cache: RuntimeMetadataCache | None = None) -> str:
    return _cache.bounded(value, max_len=max_len) if _cache is not None else sanitize_text(value, max_len=max_len)


def _event_session_id(payload: dict[str, Any], *, _cache: RuntimeMetadataCache | None = None) -> str:
    for key in ("session_id", "trace_id", "request_id"):
        value = str(payload.get(key) or "").strip()
        if value:
            return _bounded(value, _cache=_cache)
    return f"runtime-{uuid.uuid4()}"


def _runtime_observation_from_event(
    event: dict[str, Any], *, tenant_id: str, source: str = "api", _cache: RuntimeMetadataCache | None = None
) -> RuntimeObservationRecord:
    observed_at = str(event.get("event_timestamp") or event.get("observed_at") or event.get("timestamp") or _now())
    event_id = str(event.get("event_id") or event.get("observation_id") or "").strip()
    if not event_id:
        # Deterministic content-derived ID so a retried id-less runtime event
        # dedups on the observation PK instead of leaking uuid4 (audit item J).
        event_id = canonical_id(
            "runtime_event",
            tenant_id,
            event.get("source_id") or event.get("source") or source,
            event.get("session_id") or event.get("trace_id") or event.get("request_id") or "",
            observed_at,
            event.get("event_type") or event.get("type") or "runtime_event",
            event.get("tool_name") or event.get("tool") or "",
            event.get("message") or event.get("reason") or event.get("decision") or "",
        )
    summary = {key: event[key] for key in ("message", "reason", "decision", "risk", "policy", "blocked") if key in event}
    metadata_source = event.get("metadata") if isinstance(event.get("metadata"), dict) else event
    return RuntimeObservationRecord(
        tenant_id=tenant_id,
        observation_id=_bounded(event_id, _cache=_cache),
        session_id=_event_session_id(event, _cache=_cache),
        observed_at=_bounded(observed_at, max_len=80, _cache=_cache),
        source=_bounded(event.get("source_id") or event.get("source") or source, max_len=120, _cache=_cache),
        surface=_bounded(event.get("surface") or "runtime", max_len=80, _cache=_cache),
        event_type=_bounded(event.get("event_type") or event.get("type") or "runtime_event", max_len=120, _cache=_cache),
        severity=_bounded(str(event.get("severity") or "unknown").lower(), max_len=40, _cache=_cache),
        verdict=_bounded(
            event.get("verdict") or event.get("action_taken") or event.get("decision") or "observed", max_len=80, _cache=_cache
        ),
        tool_name=_bounded(event.get("tool_name") or event.get("tool") or "", max_len=200, _cache=_cache),
        agent_name=_bounded(event.get("agent_name") or event.get("agent_id") or "", max_len=200, _cache=_cache),
        trace_id=_bounded(event.get("trace_id") or "", max_len=200, _cache=_cache),
        span_id=_bounded(event.get("span_id") or "", max_len=200, _cache=_cache),
        request_id=_bounded(event.get("request_id") or "", max_len=200, _cache=_cache),
        summary=sanitize_runtime_metadata(summary, _cache=_cache),
        metadata=sanitize_runtime_metadata(metadata_source, _cache=_cache),
    )


def _persist_runtime_observations(events: list[dict[str, Any]], *, tenant_id: str, source: str = "api") -> int:
    if not events:
        return 0
    store = get_runtime_event_store()
    cache = RuntimeMetadataCache()
    records = [_runtime_observation_from_event(event, tenant_id=tenant_id, source=source, _cache=cache) for event in events]
    persisted = store.put_observations_batch(records)
    # Opt-in runtime emitter plugins receive a redacted routing envelope per
    # persisted observation (off by default; see plugin_activation). Never lets
    # a third-party emitter failure affect the persisted ingest result.
    from agent_bom.plugin_activation import fan_out_runtime_event, runtime_emitter_activation_enabled

    if runtime_emitter_activation_enabled():
        for record in records:
            fan_out_runtime_event(record)
    return persisted


def _finish_ocsf_ingest(normalized_events: list[dict[str, Any]], *, tenant_id: str) -> None:
    try:
        if normalized_events:
            _get_analytics_store().record_events(normalized_events, tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("OCSF analytics ingest skipped: %s", sanitize_text(exc))
    _persist_runtime_observations(normalized_events, tenant_id=tenant_id, source="ocsf")


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))
