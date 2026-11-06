"""Live restricted-role proof: AI advice stays inside its tenant, whatever the query asks for."""

import os
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")


@pytest.fixture
def store():
    from agent_bom.api.ai_assessment_store import PostgresAIAssessmentStore
    from agent_bom.api.postgres_common import _new_application_pool

    with _new_application_pool(min_size=1, max_size=2) as pool:
        yield PostgresAIAssessmentStore(pool=pool)


def _item(finding_id: str, verdict: str = "confirmed") -> dict:
    return {"finding_id": finding_id, "verdict": verdict, "rationale": "r"}


def _scope(tenant: str):
    from tests.test_postgres_job_evidence_revision import tenant_scope

    return tenant_scope(tenant)


def test_round_trip_latest_scan_wins_and_tenants_stay_apart(store) -> None:
    first, second = "ai-" + uuid4().hex, "ai-" + uuid4().hex
    with _scope(first):
        store.put_scan(first, "s1", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_item("a", "needs_review"), _item("b")])
        store.put_scan(first, "s2", {"status": "partial", "created_at": "2026-11-02T00:00:00+00:00"}, [_item("a", "confirmed")])
        latest = store.latest_for_findings(first, ["a", "b"])
        assert latest["a"]["verdict"] == "confirmed" and latest["a"]["scan_id"] == "s2"
        assert latest["b"]["scan_id"] == "s1"
        assert store.latest_run(first)["status"] == "partial"
    with _scope(second):
        assert store.latest_for_findings(second, ["a", "b"]) == {}
        assert store.latest_run(second) is None
        store.put_scan(second, "s1", {"status": "failed", "created_at": "2026-11-03T00:00:00+00:00"}, [_item("a", "needs_review")])
    with _scope(first):
        assert store.latest_for_findings(first, ["a"])["a"]["verdict"] == "confirmed"
        assert store.purge_tenant(first) == 5
        assert store.latest_for_findings(first, ["a"]) == {}
    with _scope(second):
        assert store.latest_for_findings(second, ["a"])["a"]["verdict"] == "needs_review"


def test_row_level_security_blocks_a_query_scoped_to_another_tenant(store) -> None:
    owner, intruder = "ai-" + uuid4().hex, "ai-" + uuid4().hex
    with _scope(owner):
        store.put_scan(owner, "s", {"status": "ok", "created_at": "2026-11-01T00:00:00+00:00"}, [_item("secret")])
    with _scope(intruder):
        # Session bound to the intruder, query names the owner: the policy still answers nothing.
        assert store.latest_for_findings(owner, ["secret"]) == {}
        assert store.latest_run(owner) is None
    with _scope(owner):
        store.purge_tenant(owner)


def test_ttl_sweep_spans_tenants_under_the_maintenance_role(store) -> None:
    first, second = "ai-" + uuid4().hex, "ai-" + uuid4().hex
    with _scope(first):
        store.put_scan(first, "old", {"status": "ok", "created_at": "2001-01-01T00:00:00+00:00"}, [_item("a")])
    with _scope(second):
        store.put_scan(second, "new", {"status": "ok", "created_at": "2099-01-01T00:00:00+00:00"}, [_item("b")])
    assert store.delete_older_than("2002-01-01T00:00:00+00:00") >= 2
    with _scope(first):
        assert store.latest_for_findings(first, ["a"]) == {}
    with _scope(second):
        assert store.latest_for_findings(second, ["b"]) != {}
        store.purge_tenant(second)
