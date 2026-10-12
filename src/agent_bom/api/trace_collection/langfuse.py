"""One bounded Langfuse v2 page; no legacy fallback or raw content persistence."""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from agent_bom.api.runtime_event_store import RuntimeObservationRecord
from agent_bom.api.trace_collection.contracts import PAGE_LIMIT, CollectionState
from agent_bom.api.trace_collection.retry import provider_retry_after
from agent_bom.runtime.egress_transport import build_pinned_sync_client
from agent_bom.security import sanitize_text
from agent_bom.trace_connectors import TraceConnectorError

MAX_RESPONSE_BYTES = 2_000_000


class ProviderFailureError(TraceConnectorError):
    def __init__(self, code: str, retry_after: float = 0) -> None:
        self.retry_after = retry_after
        self.code = code
        super().__init__("Trace collection provider request failed.")


def identity(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def _text(row: dict[str, Any], key: str, *, optional: bool = False) -> str:
    value = row.get(key)
    if optional and value is None:
        return ""
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ProviderFailureError("invalid_record")
    return value


def _record(tenant: str, connection: str, row: dict[str, Any], state: CollectionState) -> RuntimeObservationRecord:
    span, trace, name = (_text(row, key) for key in ("id", "traceId", "name"))
    try:
        observed = datetime.fromisoformat(_text(row, "startTime").replace("Z", "+00:00"))
        if observed.tzinfo is None or not datetime.fromisoformat(state.window_start) <= observed < datetime.fromisoformat(state.window_end):
            raise ValueError("timestamp outside requested window")
    except ValueError as exc:
        raise ProviderFailureError("invalid_timestamp") from exc
    parent = _text(row, "parentObservationId", optional=True)
    # Stable source identity is not independently verified workload identity.
    return RuntimeObservationRecord(
        tenant_id=tenant,
        observation_id="trace:" + identity(tenant, connection, trace, span),
        session_id="trace:" + identity(tenant, connection, trace),
        observed_at=observed.astimezone(timezone.utc).isoformat(),
        source="langfuse",
        event_type="tool_call",
        tool_name=sanitize_text(name, max_len=256),
        trace_id=trace,
        span_id=span,
        metadata={
            "connection_id": connection,
            "parent_span_id": parent,
            "identity_basis": "provider_record",
            "correlation_basis": "name_match_only",
            "schema_version": "trace.observation.v1",
        },
    )


def _payload(client: httpx.Client, credentials: dict[str, str], state: CollectionState) -> Any:
    params = {
        "limit": str(PAGE_LIMIT),
        "fields": "core,basic",
        "type": "TOOL",
        "fromStartTime": state.window_start,
        "toStartTime": state.window_end,
    }
    if state.cursor:
        params["cursor"] = state.cursor
    url = credentials["host"].rstrip("/") + "/api/public/v2/observations"
    deadline = time.monotonic() + 25
    with client.stream(
        "GET", url, params=params, auth=(credentials["public_key"], credentials["secret_key"]), timeout=httpx.Timeout(10, connect=5)
    ) as response:
        if response.status_code != 200:
            code = {401: "access_denied", 403: "access_denied", 429: "rate_limited", 404: "unsupported_api"}.get(
                response.status_code, "provider_unavailable"
            )
            raise ProviderFailureError(code, provider_retry_after(response.headers.get("Retry-After"), now=time.time()))
        data = bytearray()
        for chunk in response.iter_bytes(chunk_size=65536):
            data.extend(chunk)
            if time.monotonic() >= deadline:
                raise ProviderFailureError("provider_timeout")
            if len(data) > MAX_RESPONSE_BYTES:
                raise ProviderFailureError("response_too_large")
        return json.loads(data)


def fetch_page(
    tenant: str, connection: str, credentials: dict[str, str], state: CollectionState, *, client: httpx.Client | None = None
) -> tuple[list[RuntimeObservationRecord], str | None]:
    parts = urlsplit(credentials["host"])
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ProviderFailureError("invalid_endpoint")
    owns = client is None
    resolved = client or build_pinned_sync_client(allow_private_networks=False, timeout=10)
    try:
        payload = _payload(resolved, credentials, state)
    except ProviderFailureError:
        raise
    except (httpx.HTTPError, ValueError, OSError) as exc:
        raise ProviderFailureError("provider_unavailable") from exc
    finally:
        if owns:
            resolved.close()
    if not isinstance(payload, dict) or not isinstance(payload.get("meta"), dict) or not isinstance(payload.get("data"), list):
        raise ProviderFailureError("invalid_page")
    cursor = payload["meta"].get("cursor")
    if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 8192 or cursor == state.cursor):
        raise ProviderFailureError("invalid_cursor")
    if len(payload["data"]) > PAGE_LIMIT:
        raise ProviderFailureError("invalid_page")
    records = []
    for row in payload["data"]:
        if not isinstance(row, dict) or row.get("type") != "TOOL":
            raise ProviderFailureError("invalid_record")
        records.append(_record(tenant, connection, row, state))
    return records, cursor
