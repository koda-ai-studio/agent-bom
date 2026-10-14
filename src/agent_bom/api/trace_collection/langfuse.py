"""One bounded Langfuse v2 page; no legacy fallback or raw content persistence."""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page
from agent_bom.api.runtime_event_store import RuntimeObservationRecord
from agent_bom.api.trace_collection.contracts import PAGE_LIMIT, CollectionState
from agent_bom.api.trace_collection.normalized_events import tenant_principal
from agent_bom.api.trace_collection.retry import provider_retry_after
from agent_bom.runtime.egress_transport import build_pinned_sync_client
from agent_bom.runtime.native_trace_spans import native_span
from agent_bom.trace_connectors import TraceConnectorError, resolve_trace_project

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


def _validate_record(row: dict[str, Any], state: CollectionState) -> None:
    for key in ("id", "traceId", "name", "type"):
        _text(row, key)
    _text(row, "parentObservationId", optional=True)
    try:
        observed = datetime.fromisoformat(_text(row, "startTime").replace("Z", "+00:00"))
        if observed.tzinfo is None or not datetime.fromisoformat(state.window_start) <= observed < datetime.fromisoformat(state.window_end):
            raise ValueError("timestamp outside requested window")
    except ValueError as exc:
        raise ProviderFailureError("invalid_timestamp") from exc


def _payload(client: httpx.Client, credentials: dict[str, str], state: CollectionState) -> Any:
    params = {
        "limit": str(PAGE_LIMIT),
        "fields": "core,basic,time,metadata,model,usage",
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
        rows, cursor = _validate_page(payload, state)
        project = resolve_trace_project("langfuse", credentials, client=resolved)
        scope = TraceImportScope(
            tenant_id=tenant,
            provider="langfuse",
            connection_id=connection,
            endpoint=credentials["host"],
            project_id=project,
            account_id=credentials.get("scope_account_id", ""),
            environment=credentials.get("scope_environment", ""),
            cloud_provider=credentials.get("scope_cloud_provider", ""),
        )
        principal = tenant_principal(tenant)
        prepared = prepare_trace_page(
            {"spans": [native_span(row, provider="langfuse", include_content=False, principal=principal) for row in rows]},
            scope=scope,
            collected_at=datetime.now(timezone.utc).isoformat(),
        )
        if prepared.rejected:
            raise ProviderFailureError("invalid_record")
        return prepared.observations, cursor
    except ProviderFailureError:
        raise
    except (httpx.HTTPError, ValueError, OSError, TraceConnectorError) as exc:
        raise ProviderFailureError("provider_unavailable") from exc
    finally:
        if owns:
            resolved.close()


def _validate_page(payload: Any, state: CollectionState) -> tuple[list[dict[str, Any]], str | None]:
    if not isinstance(payload, dict) or not isinstance(payload.get("meta"), dict) or not isinstance(payload.get("data"), list):
        raise ProviderFailureError("invalid_page")
    cursor = payload["meta"].get("cursor")
    if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 8192 or cursor == state.cursor):
        raise ProviderFailureError("invalid_cursor")
    if len(payload["data"]) > PAGE_LIMIT:
        raise ProviderFailureError("invalid_page")
    for row in payload["data"]:
        if not isinstance(row, dict):
            raise ProviderFailureError("invalid_record")
        _validate_record(row, state)
    return payload["data"], cursor
