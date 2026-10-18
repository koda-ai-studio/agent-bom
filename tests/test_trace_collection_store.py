"""A provider page and its resume checkpoint are one tenant-bound commit."""

from dataclasses import replace

import pytest

from agent_bom.api.runtime_event_store import RuntimeObservationRecord, SQLiteRuntimeEventStore
from agent_bom.api.storage.sql import SQLiteBackend
from agent_bom.api.trace_collection.contracts import CollectionConflictError, CollectionState
from agent_bom.api.trace_collection.store import TraceCollectionStore


@pytest.fixture
def stores(tmp_path):
    runtime = SQLiteRuntimeEventStore(str(tmp_path / "events.db"))
    collection = TraceCollectionStore(SQLiteBackend(str(tmp_path / "events.db")))
    collection.init_schema()
    return runtime, collection


def initial():
    return CollectionState(scope_digest="project-a", window_start="2026-10-10T00:00:00+00:00", window_end="2026-10-11T00:00:00+00:00")


def observation(tenant="a", key="event-1"):
    return RuntimeObservationRecord(tenant, key, "session-1", "2026-10-10T12:00:00+00:00", source="langfuse", tool_name="read")


def test_page_and_checkpoint_survive_restart_without_replay(stores):
    runtime, store = stores
    state = store.claim("a", "connection", initial(), now=100)
    done = store.commit("a", "connection", state, [observation()], next_cursor="page-2", now=101)
    assert done.persisted == 1 and done.cursor == "page-2"
    state = store.claim("a", "connection", initial(), now=102)
    done = store.commit("a", "connection", state, [observation()], next_cursor=None, now=103)
    assert done.persisted == 1 and done.completed_until == initial().window_end
    assert len(runtime.list_observations("a")) == 1
    assert runtime.get_session("a", "session-1").observation_count == 1


def test_page_rollups_do_bounded_sql_work_per_session_and_preserve_replay(stores):
    runtime, store = stores
    first = store.claim("a", "connection", initial(), now=100)
    store.commit("a", "connection", first, [observation()], next_cursor="page-2", now=101)
    records = [
        replace(observation(key=f"page-2-{i}"), session_id=f"session-{1 + i % 2}", verdict="denied" if i % 2 else "allowed")
        for i in range(100)
    ]
    # A noisy page must not repeatedly deserialize and rewrite the same rollup.
    statements = []
    store.backend._conn().set_trace_callback(statements.append)
    claim = store.claim("a", "connection", initial(), now=102)
    done = store.commit("a", "connection", claim, records, next_cursor="page-3", now=103)
    store.backend._conn().set_trace_callback(None)
    reads = [sql for sql in statements if sql.startswith("SELECT data FROM runtime_sessions")]
    writes = [sql for sql in statements if sql.startswith("INSERT INTO runtime_sessions")]
    assert len(reads) <= 2
    assert len(writes) <= 2
    assert done.persisted == 101
    assert runtime.get_session("a", "session-1").observation_count == 51
    assert runtime.get_session("a", "session-1").verdicts == {"allowed": 50, "observed": 1}
    assert runtime.get_session("a", "session-2").verdicts == {"denied": 50}
    assert runtime.get_session("b", "session-1") is None
    claim = store.claim("a", "connection", initial(), now=104)
    replay = store.commit("a", "connection", claim, records, next_cursor=None, now=105)
    assert replay.persisted == 101
    assert runtime.get_session("a", "session-1").observation_count == 51


def test_conflicting_replay_rolls_back_entire_page_and_checkpoint(stores):
    runtime, store = stores
    first = store.claim("a", "connection", initial(), now=100)
    store.commit("a", "connection", first, [observation()], next_cursor="page-2", now=101)
    second = store.claim("a", "connection", initial(), now=102)
    with pytest.raises(CollectionConflictError):
        store.commit(
            "a", "connection", second, [observation(key="new"), replace(observation(), tool_name="write")], next_cursor=None, now=103
        )
    assert len(runtime.list_observations("a")) == 1
    assert store.get("a", "connection").cursor == "page-2"


@pytest.mark.parametrize("count", [100, 201])
def test_native_page_bounds_identity_reads_without_losing_replay_or_history(stores, count):
    runtime, store = stores
    records = [
        replace(
            observation(key=f"span-{i}"),
            surface="imported_trace",
            metadata={"connection_id": "connection", "project_id": "project"},
        )
        for i in range(count)
    ]
    statements = []
    claim = store.claim("a", "connection", initial(), now=100)
    store.backend._conn().set_trace_callback(statements.append)
    done = store.commit("a", "connection", claim, records, next_cursor="second", now=101)
    store.backend._conn().set_trace_callback(None)
    reads = [
        sql
        for sql in statements
        if sql.startswith("SELECT")
        and any(table in sql for table in ("runtime_observations", "runtime_observation_revisions", "trace_collection_receipts"))
    ]
    # Ten identity reads plus one constant revision-retention count per page.
    assert len(reads) <= 11, "page identity reads must be bounded rather than repeated per span"
    inserts = [sql for sql in statements if sql.startswith(("INSERT INTO runtime_observation", "INSERT INTO trace_collection_receipts"))]
    assert len(inserts) <= 3 * ((count + 99) // 100), "page inserts must use bounded batches rather than one round trip per span"
    assert done.persisted == count
    assert runtime.get_session("a", "session-1").observation_count == count
    claim = store.claim("a", "connection", initial(), now=102)
    assert store.commit("a", "connection", claim, records, next_cursor=None, now=103).persisted == count
    assert len(runtime.list_observations("a", limit=1000)) == count
    assert not runtime.list_observations("b")
    with store.backend.transaction(read_only=True) as tx:
        assert tx.execute("SELECT COUNT(*) FROM runtime_observation_revisions WHERE tenant_id=?", ("a",)).fetchone()[0] == count


def test_expired_worker_cannot_commit_after_replacement(stores):
    runtime, store = stores
    old = store.claim("a", "connection", initial(), now=100)
    with pytest.raises(CollectionConflictError):
        store.claim("a", "connection", initial(), now=101)
    new = store.claim("a", "connection", initial(), now=200)
    with pytest.raises(CollectionConflictError):
        store.commit("a", "connection", old, [observation()], next_cursor=None, now=201)
    store.commit("a", "connection", new, [observation()], next_cursor=None, now=202)
    assert len(runtime.list_observations("a")) == 1


def test_tenant_and_scope_mismatch_fail_closed(stores):
    runtime, store = stores
    state = store.claim("a", "connection", initial(), now=100)
    with pytest.raises(CollectionConflictError):
        store.commit("a", "connection", state, [observation("b")], next_cursor=None, now=101)
    assert store.get("b", "connection") is None
    assert not runtime.list_observations("b")
    with pytest.raises(CollectionConflictError):
        store.claim("a", "connection", initial().model_copy(update={"scope_digest": "project-b"}), now=200)


def test_provider_failure_retains_cursor_and_enforces_cooldown(stores):
    _, store = stores
    state = store.claim("a", "connection", initial(), now=100)
    store.fail("a", "connection", state, code="rate_limited", now=101)
    assert store.get("a", "connection").cursor is None
    with pytest.raises(CollectionConflictError):
        store.claim("a", "connection", initial(), now=102)
    retry = store.claim("a", "connection", initial(), now=200)
    assert retry.window_start == initial().window_start


def test_cursor_cycle_rolls_back_and_late_retry_cannot_renew_itself(stores):
    runtime, store = stores
    claim = store.claim("a", "connection", initial(), now=100)
    store.commit("a", "connection", claim, [], next_cursor="cursor-a", now=101)
    claim = store.claim("a", "connection", initial(), now=102)
    store.commit("a", "connection", claim, [], next_cursor="cursor-b", now=103)
    claim = store.claim("a", "connection", initial(), now=104)
    with pytest.raises(CollectionConflictError):
        store.commit("a", "connection", claim, [observation()], next_cursor="cursor-a", now=105)
    assert not runtime.list_observations("a")
    with pytest.raises(CollectionConflictError):
        store.commit("a", "connection", claim, [observation()], next_cursor=None, now=200)


def test_retention_keeps_overlap_receipts_and_bounds_import_sessions(stores, monkeypatch):
    runtime, store = stores
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "1")
    first = replace(observation(), session_id="trace:first", observed_at="2026-10-10T23:50:00+00:00")
    second = replace(first, observation_id="second", session_id="trace:second", observed_at="2026-10-10T23:55:00+00:00")
    claim = store.claim("a", "connection", initial(), now=100)
    store.commit("a", "connection", claim, [first, second], next_cursor=None, now=101)
    assert len(runtime.list_observations("a")) == 1
    assert len(runtime.list_sessions("a")) == 1
    claim = store.claim("a", "connection", initial(), now=102)
    result = store.commit("a", "connection", claim, [first, second], next_cursor=None, now=103)
    assert result.persisted == 2
    assert len(runtime.list_observations("a")) == 1


def test_native_collection_and_manual_import_share_identity_revision_and_rollup(stores):
    from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page
    from agent_bom.api.trace_import_service import import_native_pages
    from agent_bom.trace_connectors import NativeTracePage

    runtime, collection = stores
    source = TraceImportScope("a", "langfuse", "connection", "https://example.test", "project")
    payload = {
        "spans": [
            {
                "spanId": "span",
                "traceId": "trace",
                "attributes": [
                    {"key": "agent_bom.native_type", "value": {"stringValue": "TOOL"}},
                    {"key": "agent_bom.native_name", "value": {"stringValue": "read"}},
                ],
            }
        ]
    }
    imported = import_native_pages(runtime, scope=source, fetch=lambda **kw: NativeTracePage(payload, None, 1))
    assert imported["counts"]["imported"] == 1
    original = runtime.list_observations("a")[0]
    payload["spans"][0]["status"] = {"code": 2}
    updated = prepare_trace_page(payload, scope=source, collected_at="2026-10-12T12:00:00+00:00").observations
    claim = collection.claim("a", "connection", initial(), now=100)
    result = collection.commit("a", "connection", claim, updated, next_cursor="next", now=101)
    assert result.persisted == 0
    assert len(runtime.list_observations("a")) == 1
    assert len(runtime.list_observation_revisions("a", original.observation_id)) == 2
    assert runtime.get_session("a", original.session_id).observation_count == 1
    claim = collection.claim("a", "connection", initial(), now=102)
    collection.commit("a", "connection", claim, updated, next_cursor=None, now=103)
    assert len(runtime.list_observation_revisions("a", original.observation_id)) == 2


def test_collection_rejects_changed_native_project(stores):
    from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page

    runtime, store = stores
    payload = {"spans": [{"spanId": "span", "traceId": "trace", "attributes": []}]}

    def records(project):
        return prepare_trace_page(
            payload,
            scope=TraceImportScope("a", "langfuse", "connection", "https://example.test", project),
            collected_at="2026-10-12T00:00:00+00:00",
        ).observations

    claim = store.claim("a", "connection", initial(), now=100)
    store.commit("a", "connection", claim, records("project-a"), next_cursor="next", now=101)
    claim = store.claim("a", "connection", initial(), now=102)
    with pytest.raises(CollectionConflictError, match="project"):
        store.commit("a", "connection", claim, records("project-b"), next_cursor=None, now=103)
    assert store.get("a", "connection").pages == 1
    assert len(runtime.list_observations("a")) == 1


def test_collection_scope_includes_configured_cloud_binding():
    from agent_bom.api.trace_collection.service import scope

    credentials = {"host": "https://example.test", "public_key": "pk"}
    for field in ("project", "scope_account_id", "scope_environment", "scope_cloud_provider"):
        assert scope(credentials) != scope({**credentials, field: "changed"})


def test_existing_main_checkpoint_keeps_its_scope_when_no_optional_binding_changes(stores):
    from agent_bom.api.trace_collection.langfuse import identity
    from agent_bom.api.trace_collection.service import scope

    _, store = stores
    credentials = {"host": "https://cloud.langfuse.com/", "public_key": "project-key"}
    old = initial().model_copy(update={"scope_digest": identity("https://cloud.langfuse.com", "project-key")})
    claim = store.claim("a", "connection", old, now=100)
    store.commit("a", "connection", claim, [], next_cursor="old-cursor", now=101)
    resumed = store.claim("a", "connection", old.model_copy(update={"scope_digest": scope(credentials)}), now=102)
    assert resumed.cursor == "old-cursor"
    assert resumed.pages == 1
    for field in ("project", "scope_account_id", "scope_environment", "scope_cloud_provider"):
        assert scope({**credentials, field: "changed"}) != old.scope_digest


def test_collected_native_revision_history_is_bounded(stores, monkeypatch):
    runtime, store = stores
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "2")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_TRACE_REVISIONS", "3")
    native = {"project_id": "project", "connection_id": "connection"}
    for i in range(6):
        span = replace(observation(key=f"span-{i}"), surface="imported_trace", observed_at=f"2026-10-10T12:0{i}:00+00:00", metadata=native)
        claim = store.claim("a", "connection", initial(), now=100 + 2 * i)
        store.commit("a", "connection", claim, [span], next_cursor=f"page-{i + 2}", now=101 + 2 * i)
    retained = {i: len(runtime.list_observation_revisions("a", f"span-{i}")) for i in range(6)}
    assert sum(retained.values()) <= 3
    assert retained[4] == retained[5] == 1
    assert retained[0] == 0


@pytest.mark.parametrize("native", [False, True])
def test_page_write_never_sleeps_with_a_transaction_open(stores, monkeypatch, native):
    runtime, store = stores
    state = store.claim("a", "connection", initial(), now=100)
    sleeps = []

    def observe_sleep(delay):
        sleeps.append(store.backend._conn().in_transaction)

    monkeypatch.setattr("agent_bom.api.storage.cooperative.time.sleep", observe_sleep)
    records = [observation(key=f"event-{i}") for i in range(65)]
    if native:
        records = [
            replace(record, surface="imported_trace", metadata={"project_id": "project", "connection_id": "connection"})
            for record in records
        ]
    done = store.commit("a", "connection", state, records, next_cursor=None, now=101)
    assert done.persisted == 65
    assert sleeps == [False, False], "handoffs belong between preparation batches, outside the transaction"
