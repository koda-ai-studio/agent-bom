"""Native trace-pull connectors for LLM-observability platforms.

Teams already sending agent traces to an LLM-observability platform should not
have to re-wire an OTLP exporter to get agent-bom correlation. These connectors
*pull* traces from Langfuse and LangSmith via their REST APIs and adapt them
into the flat OTLP span shape that :mod:`agent_bom.otel_ingest` already parses —
so the same parse + span-identity correlation + (opt-in) content screening
pipeline runs regardless of how the trace arrived.

Design:
- The OTel span parsing in ``otel_ingest`` is reused; only the API clients are
  new. Each connector maps its native records to ``{"spans": [ ...OTLP... ]}``.
- Credentials (Langfuse public/secret key, LangSmith API key) are passed in by
  the caller from the secret store / request body. They are used for auth only
  and are **never logged**.
- The HTTP client is injectable (``client=``) so tests exercise the mapping with
  mocked HTTP and no network.
- Metadata (tool name, server, package) is always mapped. Free-text content
  (tool output / model completion) is mapped **only** when ``include_content``
  is set, mirroring the opt-in, privacy-safe content posture of the ingest path.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, cast

from agent_bom.runtime.native_trace_spans import native_span

logger = logging.getLogger(__name__)

LANGFUSE = "langfuse"
LANGSMITH = "langsmith"

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 1000
_HTTP_TIMEOUT = 20.0


class TraceConnectorError(RuntimeError):
    """Raised when a trace connector cannot authenticate or reach its API."""


class _TraceConnectorHTTPError(TraceConnectorError):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"trace connector returned HTTP {status}")


class TraceConnectorValidationError(TraceConnectorError):
    """Raised when caller-supplied connector input is invalid (bad request).

    Distinct from the base error so the API layer can map it to a 4xx (client
    error) rather than a 5xx: an unsafe or malformed connector URL is the
    caller's fault, not an upstream failure.
    """


def _validate_pull_url(url: str) -> None:
    """Reject unsafe connector base URLs before any server-side request.

    The connector host is caller-supplied, so an unvalidated fetch lets a
    ``runtime_ingest`` caller point the control plane at internal services or
    cloud-metadata endpoints (SSRF). ``validate_url`` enforces HTTPS and blocks
    private / loopback / link-local / reserved / metadata targets (incl. DNS
    rebinding). The rejection message is static — the raw URL is never echoed —
    so no caller-controlled value leaks back into the response or logs.
    """
    from agent_bom.security import SecurityError, validate_url

    try:
        validate_url(url, allow_private=False)
    except SecurityError as exc:
        raise TraceConnectorValidationError("connector host failed URL validation (must be a public HTTPS endpoint)") from exc


class _HttpResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


class _HttpClient(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> _HttpResponse: ...


def list_trace_connectors() -> list[dict[str, Any]]:
    """Describe the available native trace-pull connectors."""
    return [
        {
            "name": LANGFUSE,
            "kind": "llm_observability",
            "auth_fields": ["host", "public_key", "secret_key"],
            "supports_content": True,
        },
        {
            "name": LANGSMITH,
            "kind": "llm_observability",
            "auth_fields": ["api_key", "api_url", "project"],
            "supports_content": True,
        },
    ]


def _bounded_limit(limit: int) -> int:
    return max(1, min(int(limit or _DEFAULT_LIMIT), _MAX_LIMIT))


def _client_or_default(client: _HttpClient | None) -> tuple[_HttpClient, bool]:
    if client is not None:
        return client, False
    import httpx

    return cast("_HttpClient", httpx.Client(timeout=_HTTP_TIMEOUT)), True


def _call_json(client: _HttpClient, method: str, url: str, **kwargs: Any) -> Any:
    try:
        resp = client.request(method, url, timeout=_HTTP_TIMEOUT, **kwargs)
    except Exception as exc:  # noqa: BLE001 — surface a clean, credential-free error
        raise TraceConnectorError(f"trace connector request failed: {type(exc).__name__}") from exc
    status = getattr(resp, "status_code", 0)
    if not 200 <= status < 300:
        raise _TraceConnectorHTTPError(status)
    try:
        return resp.json()
    except (ValueError, TypeError) as exc:
        raise TraceConnectorError("trace connector returned invalid JSON") from exc


def _records(payload: Any, key: str) -> list[dict[str, Any]]:
    records = payload.get(key) if isinstance(payload, dict) else payload
    if not isinstance(records, list) or any(
        not isinstance(row, dict)
        or not isinstance(row.get("id"), str)
        or not row["id"].strip()
        or not isinstance(row.get("name"), str)
        or not row["name"].strip()
        for row in records
    ):
        raise TraceConnectorError("trace connector returned invalid records")
    return records


# ─── Langfuse ──────────────────────────────────────────────────────────────


def _langfuse_observation_to_span(obs: dict[str, Any], *, include_content: bool) -> dict[str, Any] | None:
    return native_span(obs, provider=LANGFUSE, include_content=include_content)


def fetch_langfuse_traces(
    *,
    host: str,
    public_key: str,
    secret_key: str,
    limit: int = _DEFAULT_LIMIT,
    include_content: bool = False,
    client: _HttpClient | None = None,
) -> dict[str, Any]:
    """Pull recent Langfuse observations and adapt them to flat OTLP spans.

    ``public_key`` / ``secret_key`` are used for HTTP Basic auth only and are
    never logged. Returns ``{"spans": [...]}`` for ``otel_ingest`` to parse.
    """
    if not host or not public_key or not secret_key:
        raise TraceConnectorError("langfuse connector requires host, public_key and secret_key")
    base = host.rstrip("/")
    _validate_pull_url(base)
    url = f"{base}/api/public/v2/observations"
    end = datetime.now(timezone.utc)
    window = {"fromStartTime": (end - timedelta(days=1)).isoformat(), "toStartTime": end.isoformat()}
    params = {
        "limit": _bounded_limit(limit),
        **window,
        "fields": "core,basic,metadata" + (",io" if include_content else ""),
        "expandMetadata": "server,mcp_server,package,dependency",
    }
    resolved, owns = _client_or_default(client)
    try:
        try:
            payload = _call_json(resolved, "GET", url, params=params, auth=(public_key, secret_key))
        except _TraceConnectorHTTPError as exc:
            # v3 self-hosted instances have no v2 route. Never downgrade on
            # authorization, rate-limit, retired-route or upstream failures.
            if exc.status != 404:
                raise
            payload = _call_json(
                resolved,
                "GET",
                f"{base}/api/public/observations",
                params={"limit": _bounded_limit(limit), **window},
                auth=(public_key, secret_key),
            )
    finally:
        if owns:
            getattr(resolved, "close", lambda: None)()
    records = _records(payload, "data")
    spans: list[dict[str, Any]] = []
    for obs in records[: _bounded_limit(limit)]:
        span = _langfuse_observation_to_span(obs, include_content=include_content)
        if span is not None:
            spans.append(span)
    logger.info("langfuse trace pull: %d spans", len(spans))
    return {"spans": spans}


# ─── LangSmith ─────────────────────────────────────────────────────────────


def _langsmith_run_to_span(run: dict[str, Any], *, include_content: bool) -> dict[str, Any] | None:
    return native_span(run, provider=LANGSMITH, include_content=include_content)


def fetch_langsmith_traces(
    *,
    api_key: str,
    api_url: str = "https://api.smith.langchain.com",
    project: str | None = None,
    limit: int = _DEFAULT_LIMIT,
    include_content: bool = False,
    client: _HttpClient | None = None,
) -> dict[str, Any]:
    """Pull recent LangSmith runs and adapt them to flat OTLP spans.

    ``api_key`` is sent as the ``x-api-key`` header only and is never logged.
    Returns ``{"spans": [...]}`` for ``otel_ingest`` to parse.
    """
    if not api_key:
        raise TraceConnectorError("langsmith connector requires api_key")
    base = (api_url or "https://api.smith.langchain.com").rstrip("/")
    _validate_pull_url(base)
    body: dict[str, Any] = {"limit": _bounded_limit(limit)}
    resolved, owns = _client_or_default(client)
    try:
        if project:
            projects = _call_json(
                resolved,
                "GET",
                f"{base}/sessions",
                headers={"x-api-key": api_key},
                params={"name": project, "limit": 2, "include_stats": False},
            )
            if not isinstance(projects, list) or len(projects) != 1 or not isinstance(projects[0], dict):
                raise TraceConnectorError("langsmith project could not be resolved uniquely")
            project_id = projects[0].get("id")
            if not isinstance(project_id, str) or not project_id or projects[0].get("name") != project:
                raise TraceConnectorError("langsmith returned invalid project scope")
            body["session"] = [project_id]
        payload = _call_json(
            resolved,
            "POST",
            f"{base}/runs/query",
            headers={"x-api-key": api_key},
            json=body,
        )
    finally:
        if owns:
            getattr(resolved, "close", lambda: None)()
    records = _records(payload, "runs")
    spans: list[dict[str, Any]] = []
    for run in records[: _bounded_limit(limit)]:
        span = _langsmith_run_to_span(run, include_content=include_content)
        if span is not None:
            spans.append(span)
    logger.info("langsmith trace pull: %d spans", len(spans))
    return {"spans": spans}


def fetch_traces(
    provider: str,
    credentials: dict[str, Any],
    *,
    limit: int = _DEFAULT_LIMIT,
    include_content: bool = False,
    client: _HttpClient | None = None,
) -> dict[str, Any]:
    """Dispatch a trace pull to the named provider.

    ``credentials`` carries the provider's auth fields (see
    :func:`list_trace_connectors`). Values are used for auth only and never
    logged. Returns flat OTLP ``{"spans": [...]}``.
    """
    key = (provider or "").strip().lower()
    if key == LANGFUSE:
        return fetch_langfuse_traces(
            host=str(credentials.get("host", "")),
            public_key=str(credentials.get("public_key", "")),
            secret_key=str(credentials.get("secret_key", "")),
            limit=limit,
            include_content=include_content,
            client=client,
        )
    if key == LANGSMITH:
        return fetch_langsmith_traces(
            api_key=str(credentials.get("api_key", "")),
            api_url=str(credentials.get("api_url", "") or "https://api.smith.langchain.com"),
            project=(str(credentials.get("project")) if credentials.get("project") else None),
            limit=limit,
            include_content=include_content,
            client=client,
        )
    raise TraceConnectorError(f"unknown trace connector '{provider}'")


__all__ = [
    "LANGFUSE",
    "LANGSMITH",
    "TraceConnectorError",
    "TraceConnectorValidationError",
    "fetch_langfuse_traces",
    "fetch_langsmith_traces",
    "fetch_traces",
    "list_trace_connectors",
]


@dataclass(frozen=True)
class NativeTracePage:
    """A single provider page; a null cursor means the fixed window is exhausted."""

    payload: dict[str, Any]
    cursor: str | None
    fetched: int


def resolve_trace_project(provider: str, credentials: dict[str, str], *, client: _HttpClient | None = None) -> str:
    """Resolve canonical project identity from authenticated provider state."""
    base = credentials.get("host" if provider == LANGFUSE else "api_url", "").rstrip("/")
    _validate_pull_url(base)
    resolved, owns = _client_or_default(client)
    try:
        if provider == LANGFUSE:
            payload = _call_json(
                resolved, "GET", f"{base}/api/public/projects", auth=(credentials["public_key"], credentials["secret_key"])
            )
            projects = payload.get("data") if isinstance(payload, dict) else None
            project_hint = credentials.get("project", "").strip()
            if isinstance(projects, list) and project_hint:
                projects = [row for row in projects if isinstance(row, dict) and project_hint in {row.get("id"), row.get("name")}]
        elif provider == LANGSMITH and credentials.get("project"):
            projects = _call_json(
                resolved,
                "GET",
                f"{base}/sessions",
                headers={"x-api-key": credentials["api_key"]},
                params={"name": credentials["project"], "limit": 2, "include_stats": False},
            )
        else:
            raise TraceConnectorValidationError("A managed tracing project is required")
        if not isinstance(projects, list) or len(projects) != 1 or not isinstance(projects[0], dict):
            raise TraceConnectorError("Trace project could not be resolved uniquely")
        project_id = projects[0].get("id")
        if not isinstance(project_id, str) or not project_id.strip() or len(project_id) > 512:
            raise TraceConnectorError("Trace provider returned an invalid project identity")
        if provider == LANGSMITH and projects[0].get("name") != credentials["project"]:
            raise TraceConnectorError("Trace provider returned a conflicting project")
        return project_id
    finally:
        if owns:
            getattr(resolved, "close", lambda: None)()


def fetch_trace_page(
    provider: str,
    credentials: dict[str, str],
    *,
    project_id: str,
    window_start: str,
    window_end: str,
    cursor: str | None,
    limit: int = _DEFAULT_LIMIT,
    include_content: bool = False,
    client: _HttpClient | None = None,
) -> NativeTracePage:
    """Fetch one bounded native page without truncation or implicit API downgrade.

    A malformed page is rejected as a unit so its checkpoint remains retryable.
    Retry/rate-limit policy belongs to the durable importer. v2 Langfuse reads
    and v1 LangSmith runs/query have different cursor and field contracts.
    """
    start, end = (datetime.fromisoformat(value.replace("Z", "+00:00")) for value in (window_start, window_end))
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        raise TraceConnectorValidationError("Trace pull requires a fixed timezone-aware window")
    if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 8192):
        raise TraceConnectorValidationError("Trace cursor is invalid")
    base = credentials.get("host" if provider == LANGFUSE else "api_url", "").rstrip("/")
    _validate_pull_url(base)
    page_limit = min(_bounded_limit(limit), 100 if provider == LANGSMITH else _MAX_LIMIT)
    resolved, owns = _client_or_default(client)
    try:
        rows, pagination, cursor_key = _native_page_request(
            resolved, provider, credentials, base, project_id, window_start, window_end, cursor, page_limit, include_content
        )
        if (pagination is not None and not isinstance(pagination, dict)) or len(rows) > page_limit:
            raise TraceConnectorError("Trace provider returned an invalid bounded page")
        # Both native APIs signal completion by omitting a cursor object or its
        # next-cursor field. A present pagination object must still be valid.
        next_cursor = pagination.get(cursor_key) if isinstance(pagination, dict) else None
        if next_cursor is not None and (
            not isinstance(next_cursor, str) or not next_cursor or len(next_cursor) > 8192 or next_cursor == cursor
        ):
            raise TraceConnectorError("Trace provider returned an invalid or nonadvancing cursor")
        spans = [native_span(row, provider=provider, include_content=include_content) for row in rows]
        return NativeTracePage(payload={"spans": spans}, cursor=next_cursor, fetched=len(rows))
    finally:
        if owns:
            getattr(resolved, "close", lambda: None)()


def _native_page_request(
    resolved: _HttpClient,
    provider: str,
    credentials: dict[str, str],
    base: str,
    project_id: str,
    window_start: str,
    window_end: str,
    cursor: str | None,
    page_limit: int,
    include_content: bool,
) -> tuple[list[dict[str, Any]], Any, str]:
    if provider == LANGFUSE:
        params: dict[str, Any] = {
            "limit": page_limit,
            "fromStartTime": window_start,
            "toStartTime": window_end,
            "fields": "core,basic,time,metadata" + (",io" if include_content else ""),
        }
        if cursor:
            params["cursor"] = cursor
        payload = _call_json(
            resolved,
            "GET",
            f"{base}/api/public/v2/observations",
            params=params,
            auth=(credentials["public_key"], credentials["secret_key"]),
        )
        rows = _records(payload, "data")
        pagination = payload.get("meta") if isinstance(payload, dict) else None
        cursor_key = "cursor"
    elif provider == LANGSMITH:
        # Bound start_time on both sides; end_time filters completion time
        # and would incorrectly omit unfinished runs from this window.
        body: dict[str, Any] = {
            "session": [project_id],
            "limit": page_limit,
            "filter": f"and(gte(start_time, {json.dumps(window_start)}), lt(start_time, {json.dumps(window_end)}))",
            "select": [
                "id",
                "name",
                "run_type",
                "start_time",
                "end_time",
                "status",
                "error",
                "extra",
                "parent_run_id",
                "session_id",
                "trace_id",
            ],
        }
        if include_content:
            body["select"].append("outputs")
        if cursor:
            body["cursor"] = cursor
        payload = _call_json(resolved, "POST", f"{base}/runs/query", headers={"x-api-key": credentials["api_key"]}, json=body)
        rows = _records(payload, "runs")
        pagination = payload.get("cursors") if isinstance(payload, dict) else None
        cursor_key = "next"
    else:
        raise TraceConnectorValidationError("Unsupported trace provider")
    return rows, pagination, cursor_key
