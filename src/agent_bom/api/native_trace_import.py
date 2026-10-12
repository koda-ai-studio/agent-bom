"""Prepare metadata-only native observations for the existing runtime store.

The caller supplies an authenticated, resolved connection scope. Vendor fields
can narrow it but cannot change the tenant, endpoint or configured project.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.api.runtime_event_store import RuntimeObservationRecord, sanitize_runtime_metadata
from agent_bom.runtime.cloud_trace_claims import cloud_trace_claims
from agent_bom.security import sanitize_text


@dataclass(frozen=True)
class TraceImportScope:
    tenant_id: str
    provider: str
    connection_id: str
    endpoint: str
    project_id: str
    environment: str = ""
    account_id: str = ""
    cloud_provider: str = ""

    def identity_scope(self) -> dict[str, str]:
        scope = asdict(self)
        # Preserve IDs issued before cloud scope was supported.
        if not self.cloud_provider:
            scope.pop("cloud_provider")
        return scope


@dataclass(frozen=True)
class PreparedTracePage:
    observations: list[RuntimeObservationRecord]
    rejected: dict[str, int]


def _identity(scope: TraceImportScope, category: str, *parts: str) -> str:
    raw = json.dumps([scope.identity_scope(), category, *parts], sort_keys=True, separators=(",", ":"))
    return f"trace:{category}:{hashlib.sha256(raw.encode()).hexdigest()}"


def _attributes(span: dict[str, Any]) -> dict[str, str]:
    raw = span.get("attributes")
    if not isinstance(raw, list):
        return {}
    return {
        item["key"]: item["value"]["stringValue"]
        for item in raw[:100]
        if isinstance(item, dict)
        and isinstance(item.get("key"), str)
        and isinstance(item.get("value"), dict)
        and isinstance(item["value"].get("stringValue"), str)
    }


def _valid_nanos(value: object) -> str | None:
    try:
        nanos = int(str(value))
        return str(nanos) if 0 < nanos < 2**64 else None
    except (ValueError, TypeError, OverflowError):
        return None


def _event_time(span: dict[str, Any]) -> str:
    try:
        nanos = int(_valid_nanos(span.get("startTimeUnixNano")) or 0)
        if not 0 < nanos < 2**64:
            return ""
        return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=nanos // 1000)).isoformat()
    except (ValueError, TypeError, OverflowError):
        return ""


def prepare_trace_page(payload: dict[str, Any], *, scope: TraceImportScope, collected_at: str) -> PreparedTracePage:
    """Namespace native IDs; report rejected rows without silently losing them."""
    collected_at = _collection_time(scope, collected_at)
    spans = payload.get("spans")
    if not isinstance(spans, list) or len(spans) > 1000:
        raise ValueError("Trace import requires a bounded span page")
    records: list[RuntimeObservationRecord] = []
    rejected: Counter[str] = Counter()
    for span in spans:
        if not isinstance(span, dict):
            rejected["invalid_span"] += 1
            continue
        native_id, trace_id, parent = (span.get(key) or "" for key in ("spanId", "traceId", "parentSpanId"))
        if not native_id or any(not isinstance(value, str) or len(value) > 512 for value in (native_id, trace_id, parent)):
            rejected["invalid_identity"] += 1
            continue
        attrs = _attributes(span)
        if any(
            attrs.get(key) and expected and attrs[key] != expected
            for key, expected in (
                ("agent_bom.trace_provider", scope.provider),
                ("agent_bom.native_project_id", scope.project_id),
                ("agent_bom.native_environment", scope.environment),
            )
        ):
            rejected["scope_conflict"] += 1
            continue
        # A connection spanning environments still keeps identical IDs apart.
        scoped = replace(scope, environment=scope.environment or attrs.get("agent_bom.native_environment", ""))
        native_type = attrs.get("agent_bom.native_type", "unknown")
        native_name = sanitize_text(attrs.get("agent_bom.native_name", ""), max_len=300)
        observed_at = _event_time(span)
        status = span.get("status")
        code = status.get("code") if isinstance(status, dict) else None
        metadata: dict[str, Any] = {
            "schema_version": "native_trace.v1",
            "provider": scope.provider,
            "connection_id": scope.connection_id,
            "project_id": scope.project_id,
            "environment": scoped.environment,
            "account_id": scope.account_id,
            "cloud_provider": scope.cloud_provider,
            "inventory_node_id": sanitize_text(attrs.get("agent_bom.inventory_node_id", ""), max_len=512),
            "inventory_scan_id": sanitize_text(attrs.get("agent_bom.inventory_scan_id", ""), max_len=512),
            "inventory_generation": sanitize_text(attrs.get("agent_bom.inventory_generation", ""), max_len=512),
            "native_type": sanitize_text(native_type, max_len=80),
            "native_name": native_name,
            "native_trace_id": trace_id,
            "native_span_id": native_id,
            "native_parent_span_id": parent,
            "native_session_id": attrs.get("agent_bom.native_session_id", ""),
            "parent_observation_id": _identity(scoped, "span", trace_id, parent) if parent else "",
            "logical_root": {"true": True, "false": False}.get(attrs.get("agent_bom.logical_root", "")),
            "collected_at": collected_at,
            "start_time_unix_nano": _valid_nanos(span.get("startTimeUnixNano")),
            "end_time_unix_nano": _valid_nanos(span.get("endTimeUnixNano")),
            "event_time_missing": not bool(observed_at),
            "type_basis": attrs.get("agent_bom.type_basis", "unknown"),
        }
        cloud_claims = cloud_trace_claims(attrs, account_id=scope.account_id, provider=scope.cloud_provider)
        if cloud_claims is not None:
            metadata["cloud_trace"] = cloud_claims
        records.append(
            RuntimeObservationRecord(
                tenant_id=scope.tenant_id,
                observation_id=_identity(scoped, "span", trace_id, native_id),
                session_id=_identity(scoped, "trace", trace_id) if trace_id else _identity(scoped, "untraced", native_id),
                observed_at=observed_at or collected_at,
                source=scope.provider,
                surface="imported_trace",
                event_type="native_span",
                verdict="error" if code == 2 else "success" if code == 1 else "unknown",
                tool_name=native_name if native_type.lower() == "tool" else "",
                trace_id=sanitize_text(trace_id, max_len=512),
                span_id=sanitize_text(native_id, max_len=512),
                summary={"message": native_name},
                metadata=sanitize_runtime_metadata(metadata),
            )
        )
    return PreparedTracePage(observations=records, rejected=dict(sorted(rejected.items())))


def _collection_time(scope: TraceImportScope, collected_at: str) -> str:
    if scope.provider not in {"langfuse", "langsmith"} or any(
        not isinstance(value, str) or not value or len(value) > 2048
        for value in (scope.tenant_id, scope.connection_id, scope.endpoint, scope.project_id)
    ):
        raise ValueError("Resolved trace connection scope is required")
    moment = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("Trace collection time must include a timezone")
    return moment.astimezone(timezone.utc).isoformat()
