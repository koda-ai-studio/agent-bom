"""Webhook subscription reads and deletes are scoped to the tenant in the store, not only in the route."""

from __future__ import annotations

import pytest

from agent_bom.api.webhook_store import InMemoryWebhookSubscriptionStore, SQLiteWebhookSubscriptionStore, WebhookSubscription


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryWebhookSubscriptionStore()
    return SQLiteWebhookSubscriptionStore(str(tmp_path / "webhooks.db"))


def test_another_tenant_cannot_read_or_delete_a_subscription(store):
    store.put(
        WebhookSubscription(subscription_id="whsub_1", tenant_id="tenant-a", url="https://hooks.example/a", signing_secret="placeholder")
    )
    assert store.get("whsub_1", tenant_id="tenant-b") is None
    assert store.delete("whsub_1", tenant_id="tenant-b") is False
    kept = store.get("whsub_1", tenant_id="tenant-a")
    assert kept is not None and kept.tenant_id == "tenant-a"
    assert store.delete("whsub_1", tenant_id="tenant-a") is True
    assert store.get("whsub_1", tenant_id="tenant-a") is None


def test_another_tenant_cannot_toggle_a_subscription(store):
    from agent_bom.api.webhook_store import set_subscription_status

    store.put(
        WebhookSubscription(subscription_id="whsub_1", tenant_id="tenant-a", url="https://hooks.example/a", signing_secret="placeholder")
    )
    assert set_subscription_status(store, "whsub_1", tenant_id="tenant-b", status="disabled") is None
    assert store.get("whsub_1", tenant_id="tenant-a").status == "active"
