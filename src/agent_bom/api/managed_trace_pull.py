"""Managed trace import HTTP orchestration; credentials stay server-side."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import HTTPException

from agent_bom import trace_connectors as connectors
from agent_bom.api import audit_log
from agent_bom.api.native_trace_import import TraceImportScope
from agent_bom.api.runtime_event_store import RuntimeEventStore
from agent_bom.api.storage.runtime_trace_imports import TraceImportConflictError
from agent_bom.api.trace_collection.normalized_events import signals_by_span, stamp_page_signals
from agent_bom.api.trace_collection.trace_evidence import record_native_evidence
from agent_bom.api.trace_collection.trace_findings import FindingSink
from agent_bom.api.trace_import_service import import_native_pages
from agent_bom.otel_ingest import parse_otel_traces
from agent_bom.runtime_correlation import correlate_spans_to_attack_paths
from agent_bom.security import sanitize_error


def _validate(body: dict[str, Any]) -> int:
    pages = body.get("max_pages", 1)
    if isinstance(pages, bool) or not isinstance(pages, int) or not 1 <= pages <= 5:
        raise HTTPException(status_code=400, detail="'max_pages' must be an integer between 1 and 5")
    if isinstance(body.get("limit", 50), bool) or not isinstance(body.get("limit", 50), int):
        raise HTTPException(status_code=400, detail="'limit' must be an integer")
    if any(body.get(key) is not None and not isinstance(body[key], str) for key in ("import_id", "window_start", "window_end")):
        raise HTTPException(status_code=400, detail="Import identifier and window bounds must be strings")
    return pages


def managed_trace_pull(
    *,
    provider: str,
    body: dict[str, Any],
    credentials: dict[str, str],
    tenant_id: str,
    actor: str,
    store: RuntimeEventStore,
    limit: int,
    screen_content: bool,
    screen: Callable[[dict[str, Any]], list[dict[str, Any]]],
    findings: Callable[[], Any],
    identities: Callable[[], Any],
    finding_sink: FindingSink | None = None,
) -> dict[str, Any]:
    max_pages = _validate(body)
    audit = dict(actor=actor, tenant_id=tenant_id, resource=f"trace_connection/{body['connection_id']}", provider=provider.strip().lower())
    try:
        result = _import(provider, body, credentials, tenant_id, store, limit, screen_content, max_pages, screen, findings, identities)
        result["normalized"] = record_native_evidence(result.pop("native_spans"), tenant_id=tenant_id, sink=finding_sink)
    except (ValueError, connectors.TraceConnectorError, TraceImportConflictError) as exc:
        conflict = isinstance(exc, TraceImportConflictError)
        invalid = isinstance(exc, (ValueError, connectors.TraceConnectorValidationError))
        audit_log.log_action("trace_import.pull", **audit, outcome="conflict" if conflict else "rejected" if invalid else "failed")
        raise HTTPException(status_code=409 if conflict else 400 if invalid else 502, detail=sanitize_error(exc)) from exc
    imported = result["import"]
    audit_log.log_action(
        "trace_import.pull",
        **audit,
        outcome=imported["status"],
        import_id=imported["import_id"],
        **{key: imported["counts"][key] for key in ("fetched", "imported", "updated", "unchanged", "rejected", "failed_pages")},
    )
    return result


def _import(
    provider: str,
    body: dict[str, Any],
    credentials: dict[str, str],
    tenant_id: str,
    store: RuntimeEventStore,
    limit: int,
    screen_content: bool,
    max_pages: int,
    screen: Callable[[dict[str, Any]], list[dict[str, Any]]],
    findings: Callable[[], Any],
    identities: Callable[[], Any],
) -> dict[str, Any]:
    project_id = connectors.resolve_trace_project(provider, credentials)
    scope = TraceImportScope(
        tenant_id=tenant_id,
        provider=provider.strip().lower(),
        connection_id=str(body["connection_id"]),
        endpoint=credentials.get("host" if provider == "langfuse" else "api_url", ""),
        project_id=project_id,
        account_id=credentials.get("scope_account_id", ""),
        environment=credentials.get("scope_environment", ""),
        cloud_provider=credentials.get("scope_cloud_provider", ""),
    )
    native_spans: list[dict[str, Any]] = []
    content_findings: list[dict[str, Any]] = []

    def observe_page(payload: dict[str, Any]) -> None:
        spans = payload.get("spans")
        if isinstance(spans, list):
            native_spans.extend(span for span in spans if isinstance(span, dict))
            if screen_content:
                screened = screen({"spans": spans})
                stamp_page_signals(spans, signals_by_span(screened))
                content_findings.extend(screened)

    imported = import_native_pages(
        store,
        scope=scope,
        import_id=body.get("import_id"),
        window_start=body.get("window_start"),
        window_end=body.get("window_end"),
        max_pages=max_pages,
        fetch=lambda **args: connectors.fetch_trace_page(
            provider, credentials, project_id=project_id, limit=limit, include_content=screen_content, **args
        ),
        on_page=observe_page,
    )
    candidates = correlate_spans_to_attack_paths(parse_otel_traces({"spans": native_spans}), findings(), nhi_by_credential=identities())
    return {
        "schema_version": "observability.trace_connectors.v1",
        "tenant_id": tenant_id,
        "provider": provider.strip().lower(),
        "pulled_spans": imported["counts"]["fetched"],
        "content_screened": screen_content,
        "attack_paths": [path.to_dict() for path in candidates],
        "content_findings": content_findings,
        "import": imported,
        "native_spans": native_spans,
    }
