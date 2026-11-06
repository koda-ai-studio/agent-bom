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


def test_explain_rate_and_budget_are_shared_across_workers(monkeypatch) -> None:
    """A real shared store: separate limiter instances, as separate workers hold, draw on one allowance."""
    from concurrent.futures import ThreadPoolExecutor

    from agent_bom.api import ai_explain_limits

    monkeypatch.setenv("AGENT_BOM_AI_EXPLAIN_PER_MINUTE", "3")
    monkeypatch.setenv("AGENT_BOM_AI_EXPLAIN_PER_DAY", "1000")
    tenant, other = "ai-" + uuid4().hex, "ai-" + uuid4().hex
    ai_explain_limits.reset_explain_limits()
    minute, _day = ai_explain_limits._stores()
    assert type(minute).__name__ == "PostgresRateLimitStore", "the shared store, not the process-local one"
    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(lambda _i: ai_explain_limits.consume_explain_allowance(tenant), range(10)))
    assert sum(item is None for item in outcomes) == 3, "exactly the allowance passes under concurrency"
    ai_explain_limits.reset_explain_limits()  # a new worker sees the same count
    denied = ai_explain_limits.consume_explain_allowance(tenant)
    assert denied is not None and denied.retry_after_seconds == 60
    assert ai_explain_limits.consume_explain_allowance(other) is None, "another tenant has its own allowance"

    monkeypatch.setenv("AGENT_BOM_AI_EXPLAIN_PER_MINUTE", "1000")
    monkeypatch.setenv("AGENT_BOM_AI_EXPLAIN_PER_DAY", "2")
    budget_tenant = "ai-" + uuid4().hex
    ai_explain_limits.reset_explain_limits()
    assert ai_explain_limits.consume_explain_allowance(budget_tenant) is None
    assert ai_explain_limits.consume_explain_allowance(budget_tenant) is None
    over = ai_explain_limits.consume_explain_allowance(budget_tenant)
    assert over is not None and "budget" in over.message
    ai_explain_limits.reset_explain_limits()


def test_a_limiter_outage_denies_the_model_call(monkeypatch) -> None:
    from agent_bom.api import ai_explain_limits

    class Down:
        def consume_if_below(self, *_args):
            raise RuntimeError("shared limiter down")

    monkeypatch.setattr(ai_explain_limits, "_stores", lambda: (Down(), Down()))
    denied = ai_explain_limits.consume_explain_allowance("ai-" + uuid4().hex)
    assert denied is not None and "could not be checked" in denied.message
