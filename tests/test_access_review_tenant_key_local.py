"""In-memory access reviews key campaigns and items by (tenant_id, id), like the SQLite and Postgres tables."""

from __future__ import annotations

import pytest

from agent_bom.api.access_review import AccessReviewCampaign, AccessReviewItem, InMemoryAccessReviewStore, SQLiteAccessReviewStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return InMemoryAccessReviewStore() if request.param == "memory" else SQLiteAccessReviewStore(str(tmp_path / "review.db"))


def _campaign(tenant_id: str) -> AccessReviewCampaign:
    return AccessReviewCampaign(
        campaign_id="arc_1", tenant_id=tenant_id, name=f"{tenant_id} review", status="open", created_at="2026-10-25"
    )


def _item(tenant_id: str) -> AccessReviewItem:
    return AccessReviewItem(
        item_id="ari_1",
        campaign_id="arc_1",
        tenant_id=tenant_id,
        subject_id="sa",
        subject_name=f"{tenant_id}-sa",
        subject_type="service_account",
    )


def test_the_same_ids_in_two_tenants_never_overwrite_or_leak(store):
    for tenant in ("tenant-a", "tenant-b"):
        store.put_campaign(_campaign(tenant))
        store.put_item(_item(tenant))
    assert store.get_campaign("arc_1", tenant_id="tenant-a").name == "tenant-a review"
    assert store.get_campaign("arc_1", tenant_id="tenant-b").name == "tenant-b review"
    assert [c.tenant_id for c in store.list_campaigns("tenant-a")] == ["tenant-a"]
    assert store.get_item("ari_1", tenant_id="tenant-a").subject_name == "tenant-a-sa"
    assert [i.tenant_id for i in store.list_items("arc_1", tenant_id="tenant-b")] == ["tenant-b"]


def test_a_pre_change_database_migrates_keeping_every_row(tmp_path):
    import json
    import sqlite3
    from dataclasses import asdict

    from agent_bom.api.sqlite_rekey import primary_key_columns

    path = str(tmp_path / "legacy.db")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE access_review_campaigns (campaign_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, status TEXT NOT NULL, "
            "created_at TEXT NOT NULL, due_at TEXT NOT NULL DEFAULT '', data TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE access_review_items (item_id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, tenant_id TEXT NOT NULL, "
            "subject_id TEXT NOT NULL, decision TEXT NOT NULL, data TEXT NOT NULL)"
        )
        campaign, item = _campaign("tenant-a"), _item("tenant-a")
        conn.execute(
            "INSERT INTO access_review_campaigns VALUES (?, ?, ?, ?, ?, ?)",
            ("arc_1", "tenant-a", "open", "2026-10-25", "", json.dumps(asdict(campaign))),
        )
        conn.execute(
            "INSERT INTO access_review_items VALUES (?, ?, ?, ?, ?, ?)",
            ("ari_1", "arc_1", "tenant-a", "sa", item.decision, json.dumps(asdict(item))),
        )

    store = SQLiteAccessReviewStore(path)
    with sqlite3.connect(path) as conn:
        assert primary_key_columns(conn, "access_review_campaigns") == ["tenant_id", "campaign_id"]
        assert primary_key_columns(conn, "access_review_items") == ["tenant_id", "item_id"]
    assert store.get_campaign("arc_1", tenant_id="tenant-a") == campaign
    assert store.get_item("ari_1", tenant_id="tenant-a") == item
    store.put_campaign(_campaign("tenant-b"))
    assert store.get_campaign("arc_1", tenant_id="tenant-a") == campaign
    SQLiteAccessReviewStore(path)
    assert len(SQLiteAccessReviewStore(path).list_campaigns("tenant-a")) == 1
