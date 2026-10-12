"""Durable managed imports bind every resume to its original source and window."""

import pytest

from agent_bom.api.native_trace_import import TraceImportScope
from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore
from agent_bom.trace_connectors import NativeTracePage, TraceConnectorError


def scope(**kwargs):
    return TraceImportScope(
        **{
            "tenant_id": "tenant",
            "provider": "langfuse",
            "connection_id": "source",
            "endpoint": "https://example.test",
            "project_id": "project",
            **kwargs,
        }
    )


def page(identity="span", cursor=None):
    return NativeTracePage({"spans": [{"spanId": identity, "traceId": "trace", "attributes": []}]}, cursor, 1)


def test_two_pages_resume_after_reopen_and_completed_replay_does_not_fetch(tmp_path):
    from agent_bom.api.trace_import_service import import_native_pages

    path = str(tmp_path / "runtime.db")
    calls = []

    def fetch(**kwargs):
        calls.append(kwargs)
        return page("first" if kwargs["cursor"] is None else "second", "next" if kwargs["cursor"] is None else None)

    first = import_native_pages(SQLiteRuntimeEventStore(path), scope=scope(), fetch=fetch, now="2026-10-12T00:00:00Z")
    assert first["complete"] is False
    assert first["counts"]["imported"] == 1
    second = import_native_pages(
        SQLiteRuntimeEventStore(path), scope=scope(), fetch=fetch, import_id=first["import_id"], now="2026-10-13T00:00:00Z"
    )
    assert second["complete"] is True
    assert calls[0]["window_start"] == calls[1]["window_start"]
    assert calls[0]["window_end"] == calls[1]["window_end"]
    assert calls[1]["cursor"] == "next"
    replay = import_native_pages(
        SQLiteRuntimeEventStore(path),
        scope=scope(),
        fetch=lambda **kw: pytest.fail("completed import must not fetch"),
        import_id=first["import_id"],
    )
    assert replay["counts"]["imported"] == 0
    store = SQLiteRuntimeEventStore(path)
    assert len(store.list_observations("tenant")) == 2
    assert store.list_sessions("tenant")[0].observation_count == 2


def test_failed_page_keeps_prior_evidence_and_cursor_for_retry(tmp_path):
    from agent_bom.api.trace_import_service import import_native_pages

    store = SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))
    first = import_native_pages(store, scope=scope(), fetch=lambda **kw: page(cursor="next"))
    before = store.get_trace_import("tenant", first["import_id"])

    def fail(**kwargs):
        raise TraceConnectorError("fixture upstream failure with secret")

    failed = import_native_pages(store, scope=scope(), fetch=fail, import_id=first["import_id"])
    assert failed["status"] == "partial"
    assert failed["counts"]["failed_pages"] == 1
    assert "secret" not in str(failed)
    assert store.get_trace_import("tenant", first["import_id"]) == before
    recovered = import_native_pages(store, scope=scope(), fetch=lambda **kw: page("second"), import_id=first["import_id"])
    assert recovered["complete"] is True
    assert len(store.list_observations("tenant")) == 2


@pytest.mark.parametrize(
    "change", [{"project_id": "other"}, {"tenant_id": "other"}, {"connection_id": "other"}, {"endpoint": "https://other.test"}]
)
def test_resume_rejects_changed_source_before_fetch(tmp_path, change):
    from agent_bom.api.trace_import_service import import_native_pages

    store = SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))
    first = import_native_pages(store, scope=scope(), fetch=lambda **kw: page(cursor="next"))
    with pytest.raises(ValueError, match="scope|unavailable"):
        import_native_pages(store, scope=scope(**change), import_id=first["import_id"], fetch=lambda **kw: pytest.fail("no fetch"))


def test_rejected_scope_rows_are_counted_without_creating_records(tmp_path):
    from agent_bom.api.trace_import_service import import_native_pages

    store = SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))
    bad = page()
    bad.payload["spans"][0]["attributes"] = [{"key": "agent_bom.native_project_id", "value": {"stringValue": "other"}}]
    result = import_native_pages(store, scope=scope(), fetch=lambda **kw: bad)
    assert result["counts"]["rejected"] == 1
    assert result["rejected_reasons"] == {"scope_conflict": 1}
    assert store.list_observations("tenant") == []
    assert result["complete"] is True
    assert result["coverage"] == "partial"


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_native_revision_preserves_history_without_double_counting(tmp_path, backend):
    from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore
    from agent_bom.api.trace_import_service import import_native_pages

    store = InMemoryRuntimeEventStore() if backend == "memory" else SQLiteRuntimeEventStore(str(tmp_path / "revisions.db"))
    first = page()
    import_native_pages(store, scope=scope(), fetch=lambda **kw: first, now="2026-10-12T00:00:00Z")
    finished = page()
    finished.payload["spans"][0].update(status={"code": 2}, endTimeUnixNano="1791763201000000000")
    result = import_native_pages(store, scope=scope(), fetch=lambda **kw: finished, now="2026-10-12T01:00:00Z")
    assert result["counts"]["updated"] == 1
    assert result["counts"]["imported"] == 0
    current = store.list_observations("tenant")[0]
    assert current.verdict == "error"
    assert store.get_session("tenant", current.session_id).observation_count == 1
    assert store.get_session("tenant", current.session_id).verdicts == {"error": 1}
    history = store.list_observation_revisions("tenant", current.observation_id)
    assert [row.verdict for row in history] == ["unknown", "error"]
    assert store.list_observation_revisions("other", current.observation_id) == []
    replay = import_native_pages(store, scope=scope(), fetch=lambda **kw: finished, now="2026-10-12T02:00:00Z")
    assert replay["counts"]["unchanged"] == 1
    assert len(store.list_observation_revisions("tenant", current.observation_id)) == 2
    # Replayed older content is evidence, but cannot regress the current state.
    stale = import_native_pages(store, scope=scope(), fetch=lambda **kw: first, now="2026-10-12T03:00:00Z")
    assert stale["counts"]["unchanged"] == 1
    assert store.list_observations("tenant")[0].verdict == "error"


def test_managed_pull_route_retains_native_page_and_audits_result(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from agent_bom.api.routes import observability as routes

    store = SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))
    monkeypatch.setattr(routes, "get_runtime_event_store", lambda: store)
    monkeypatch.setattr(
        routes, "pull_credentials", lambda *a, **kw: {"host": "https://example.test", "public_key": "pk", "secret_key": "private"}
    )
    monkeypatch.setattr("agent_bom.trace_connectors.resolve_trace_project", lambda *a, **kw: "project")
    monkeypatch.setattr("agent_bom.trace_connectors.fetch_trace_page", lambda *a, **kw: page())
    monkeypatch.setattr("agent_bom.trace_connectors.fetch_traces", lambda *a, **kw: {"spans": []})
    monkeypatch.setattr(routes, "_blast_radius_views_for_tenant", lambda _: [])
    monkeypatch.setattr(routes, "_nhi_by_credential_for_tenant", lambda _: {})
    audit = []
    monkeypatch.setattr("agent_bom.api.audit_log.log_action", lambda *a, **kw: audit.append((a, kw)))
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant", api_key_name="operator"))
    result = routes.pull_trace_connector(request, "langfuse", {"connection_id": "source", "screen_content": False})
    assert result["import"]["complete"] is True
    assert result["import"]["counts"]["imported"] == 1
    assert len(store.list_observations("tenant")) == 1
    assert audit[-1][0] == ("trace_import.pull",)
    assert audit[-1][1]["tenant_id"] == "tenant"
    assert "private" not in str(result) + str(audit)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_native_history_prevents_replay_after_projection_retention(tmp_path, monkeypatch, backend):
    from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore
    from agent_bom.api.trace_import_service import import_native_pages

    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "1")
    store = InMemoryRuntimeEventStore() if backend == "memory" else SQLiteRuntimeEventStore(str(tmp_path / "retention.db"))
    first = page("first")
    first.payload["spans"][0]["startTimeUnixNano"] = "1791763200000000000"
    import_native_pages(store, scope=scope(), fetch=lambda **kw: first)
    original = store.list_observations("tenant")[0]
    later = page("second")
    later.payload["spans"][0]["startTimeUnixNano"] = "1791763300000000000"
    import_native_pages(store, scope=scope(), fetch=lambda **kw: later)
    assert len(store.list_observations("tenant")) == 1
    replay = import_native_pages(store, scope=scope(), fetch=lambda **kw: first)
    assert replay["counts"]["unchanged"] == 1
    assert store.get_session("tenant", original.session_id).observation_count == 2
    assert len(store.list_observation_revisions("tenant", original.observation_id)) == 1
    first.payload["spans"][0]["status"] = {"code": 2}
    updated = import_native_pages(store, scope=scope(), fetch=lambda **kw: first)
    assert updated["counts"]["updated"] == 1
    assert store.get_session("tenant", original.session_id).observation_count == 2
    assert len(store.list_observation_revisions("tenant", original.observation_id)) == 2


def test_revision_read_route_is_tenant_scoped_and_bounded(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from agent_bom.api.routes import observability as routes
    from agent_bom.api.trace_import_service import import_native_pages

    store = SQLiteRuntimeEventStore(str(tmp_path / "history-route.db"))
    import_native_pages(store, scope=scope(), fetch=lambda **kw: page())
    record = store.list_observations("tenant")[0]
    monkeypatch.setattr(routes, "get_runtime_event_store", lambda: store)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant"))
    result = routes.list_runtime_observation_revisions(request, record.observation_id, limit=1, offset=0)
    assert result["count"] == 1
    assert routes.list_runtime_observation_revisions(request, record.observation_id, limit=1, offset=1)["count"] == 0
    request.state.tenant_id = "other"
    assert routes.list_runtime_observation_revisions(request, record.observation_id, limit=1, offset=0)["count"] == 0


def test_provider_cursor_cycle_is_rejected_after_restart_without_committing_page(tmp_path):
    from agent_bom.api.storage.runtime_trace_imports import TraceImportConflictError
    from agent_bom.api.trace_import_service import import_native_pages

    path = str(tmp_path / "cursor-cycle.db")
    first = import_native_pages(SQLiteRuntimeEventStore(path), scope=scope(), fetch=lambda **kw: page("first", "a"))
    second = import_native_pages(
        SQLiteRuntimeEventStore(path), scope=scope(), import_id=first["import_id"], fetch=lambda **kw: page("second", "b")
    )
    store = SQLiteRuntimeEventStore(path)
    before = store.get_trace_import("tenant", first["import_id"])
    with pytest.raises(TraceImportConflictError, match="cursor"):
        import_native_pages(store, scope=scope(), import_id=first["import_id"], fetch=lambda **kw: page("uncommitted", "a"))
    assert store.get_trace_import("tenant", first["import_id"]) == before
    assert len(store.list_observations("tenant")) == 2
    assert second["complete"] is False
