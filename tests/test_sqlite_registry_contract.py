"""SQLite registry contracts: retained schema, replay, isolation and secret storage."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from agent_bom.api.dataset_version_store import DatasetVersionRecord, SQLiteDatasetVersionStore
from agent_bom.api.drift_incident_store import DriftIncident, SQLiteDriftIncidentStore
from agent_bom.api.evaluation_store import EvaluationRunRecord, SQLiteEvaluationRunStore
from agent_bom.api.webhook_store import SQLiteWebhookSubscriptionStore, WebhookSubscription

CASES = {
    "dataset": (SQLiteDatasetVersionStore, DatasetVersionRecord("alpha", "dataset", "v1", "2026-01-01", "test")),
    "evaluation": (SQLiteEvaluationRunStore, EvaluationRunRecord("alpha", "evaluation", "2026-01-01", "2026-01-01")),
    "drift": (
        SQLiteDriftIncidentStore,
        DriftIncident("incident", "alpha", "blueprint", "drift_detected", 1, 1, 0, [], "2026-01-01", "2026-01-01"),
    ),
    "webhook": (
        SQLiteWebhookSubscriptionStore,
        WebhookSubscription("subscription", "alpha", "https://example.invalid", "fixture-secret", created_at="2026-01-01"),
    ),
}
SCHEMA = Path(__file__).parent / "fixtures" / "sqlite_registry_schema.json"


def read(store, kind, tenant="alpha"):
    if kind == "dataset":
        return store.get(tenant, "dataset", "v1")
    if kind == "evaluation":
        return store.get(tenant, "evaluation")
    if kind == "drift":
        return store.get(tenant, "incident")
    return store.get("subscription", tenant_id=tenant)


def schema(store):
    return [
        list(row)
        for row in store._conn.execute("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
    ]


@pytest.mark.parametrize("kind", CASES)
def test_existing_schema_reopen_replay_and_tenant_lists(tmp_path, kind, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_CONNECTIONS_KEY", raising=False)
    cls, record = CASES[kind]
    path = str(tmp_path / "registry.db")
    first = cls(path)
    assert schema(first) == json.loads(SCHEMA.read_text())[kind]
    save = first.upsert if kind == "drift" else first.put
    save(record)
    save(record)
    second = cls(path)
    restored = read(second, kind)
    assert restored == (replace(record, occurrences=2) if kind == "drift" else record)
    other_rows = second.list("beta", "dataset") if kind == "dataset" else second.list("beta")
    assert other_rows == []
    if kind != "webhook":
        assert read(second, kind, "beta") is None
        save(replace(record, tenant_id="beta"))
        assert read(second, kind, "beta").tenant_id == "beta"
        assert read(second, kind).tenant_id == "alpha"
    first._conn.close()
    second._conn.close()


def test_dataset_and_evaluation_order_filters_and_offsets(tmp_path):
    dataset = SQLiteDatasetVersionStore(str(tmp_path / "dataset.db"))
    evaluation = SQLiteEvaluationRunStore(str(tmp_path / "evaluation.db"))
    for number in range(4):
        at = f"2026-01-0{number + 1}"
        dataset.put(DatasetVersionRecord("alpha", "dataset", f"v{number}", at, "test"))
        evaluation.put(EvaluationRunRecord("alpha", f"ev{number}", at, at, dataset_id="dataset" if number % 2 else "other"))
    assert [r.version_id for r in dataset.list("alpha", "dataset")] == ["v3", "v2", "v1", "v0"]
    assert [r.evaluation_id for r in evaluation.list("alpha", limit=2, offset=1)] == ["ev2", "ev1"]
    assert [r.evaluation_id for r in evaluation.list("alpha", dataset_id="dataset", limit=1, offset=1)] == ["ev1"]
    dataset._conn.close()
    evaluation._conn.close()


def test_drift_resolve_and_reopen_preserve_lifecycle(tmp_path):
    cls, record = CASES["drift"]
    store = cls(str(tmp_path / "drift.db"))
    store.upsert(record)
    store.resolve("alpha", "incident", by="operator", note="fixed", at="2026-01-02")
    assert store.list("alpha") == []
    resolved = store.list("alpha", include_resolved=True)[0]
    assert (resolved.resolved_by, resolved.resolution_note) == ("operator", "fixed")
    store.upsert(replace(record, last_detected_at="2026-01-03"))
    reopened = store.list("alpha")[0]
    assert (reopened.resolved, reopened.occurrences, reopened.resolved_by) == (False, 1, "")
    store._conn.close()


def test_webhook_encryption_matching_and_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY", Fernet.generate_key().decode())
    cls, record = CASES["webhook"]
    store = cls(str(tmp_path / "webhook.db"))
    store.put(replace(record, event_types=["identity.*"]))
    raw = store._conn.execute("SELECT data FROM webhook_subscriptions").fetchone()[0]
    assert "fixture-secret" not in raw
    assert json.loads(raw)["signing_secret"].startswith("enc:v1:")
    assert store.get("subscription", tenant_id="alpha").signing_secret == "fixture-secret"
    assert len(store.matching("alpha", "identity.issued")) == 1
    assert store.matching("alpha", "budget.exceeded") == []
    store.put(replace(record, status="disabled"))
    assert store.list("alpha") == []
    assert len(store.list("alpha", include_disabled=True)) == 1
    assert store.delete("subscription", tenant_id="beta") is False
    assert store.delete("subscription", tenant_id="alpha") is True
    assert store.delete("subscription", tenant_id="alpha") is False
    store._conn.close()


@pytest.mark.parametrize("kind", CASES)
def test_failed_registry_write_rolls_back_and_connection_recovers(tmp_path, kind, monkeypatch):
    import sqlite3

    monkeypatch.delenv("AGENT_BOM_CONNECTIONS_KEY", raising=False)
    cls, record = CASES[kind]
    store = cls(str(tmp_path / "registry.db"))
    save = store.upsert if kind == "drift" else store.put
    with pytest.raises(sqlite3.IntegrityError):
        save(replace(record, tenant_id=None))
    assert not store._conn.in_transaction
    save(record)
    assert read(store, kind) == record
    store._conn.close()
