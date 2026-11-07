"""Auth failure state survives processes and escalates without key-based lockout."""


def test_sqlite_shared_backoff_and_expiry(tmp_path):
    from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore

    path = str(tmp_path / "limits.db")
    first, second = SQLiteAuthFailureStore(path), SQLiteAuthFailureStore(path)
    for _ in range(3):
        first.record("192.0.2.1", 100, limit=3, base=10, maximum=60)
    assert second.remaining("192.0.2.1", 101) == 9
    assert second.remaining("192.0.2.2", 101) == 0
    assert second.remaining("192.0.2.1", 111) == 0
    for _ in range(3):
        second.record("192.0.2.1", 111, limit=3, base=10, maximum=60)
    assert first.remaining("192.0.2.1", 112) == 19
    assert first.remaining("192.0.2.1", 4000) == 0


def test_audit_budget_is_shared_and_bounded(tmp_path):
    from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore

    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    assert sum(store.audit_allowed(f"192.0.2.{i}", 100) for i in range(400)) <= 100
    assert sum(store.audit_allowed("198.51.100.1", 200) for _ in range(400)) <= 3


def test_suppressed_source_receipts_do_not_exhaust_other_sources(tmp_path):
    from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore

    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    assert sum(store.audit_allowed("192.0.2.1", 100) for _ in range(100)) == 3
    assert sum(store.audit_allowed(f"198.51.100.{i}", 100) for i in range(100)) == 97
