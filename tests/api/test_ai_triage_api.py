"""AI advice over the API: off by default, tenant-scoped, role-checked, and never called on a read."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from starlette.testclient import TestClient

from agent_bom.ai_components import call_audit
from agent_bom.api import ai_explain_limits
from agent_bom.api.ai_assessment_store import InMemoryAIAssessmentStore, set_ai_assessment_store
from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes import ai as ai_routes
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode
from tests._clock_helpers import recent
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

ASSESSMENT = {
    "finding_id": "finding-1",
    "verdict": "likely_false_positive",
    "confidence": "high",
    "false_positive_likelihood": "high",
    "classification": "likely_false_positive",
    "rationale": "Installed 2.0.0 is at the fix.",
    "advisory": True,
    "schema_version": "ai.finding-assessment.v1",
    "provenance": {
        "model": "ollama/llama3.2",
        "provider": "ollama",
        "model_digest": "sha256-abc",
        "prompt_version": "ai-triage.v3",
        "dataset_version": "ai-triage-dataset.v1",
        "generated_at": "2026-11-05T00:00:00+00:00",
    },
}


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _client(tenant: str = "tenant-a", role: str = "analyst") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _job(tenant: str, *, is_kev: bool = False) -> ScanJob:
    stamp = recent("2026-11-05T00:00:00Z")
    finding = {
        "id": "finding-1",
        "finding_id": "finding-1",
        "finding_type": "CVE",
        "source": "MCP_SCAN",
        "severity": "high",
        "effective_severity": "high",
        "title": "CVE-2024-0001 in lib",
        "is_kev": is_kev,
        "cve_id": "CVE-2024-0001",
        "asset": {"name": "lib", "asset_type": "package", "identifier": "pkg:npm/lib@2.0.0"},
    }
    return ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=stamp,
        completed_at=stamp,
        request=ScanRequest(images=["lib:1"]),
        result={"findings": [finding], "blast_radius": [], "agents": [], "scan_id": str(uuid.uuid4())},
    )


@pytest.fixture()
def store():
    assessments = InMemoryAIAssessmentStore()
    set_ai_assessment_store(assessments)
    jobs = InMemoryJobStore()
    jobs.put(_job("tenant-a"))
    jobs.put(_job("tenant-b"))
    set_job_store(jobs)
    assessments.put_scan(
        "tenant-a", "scan-a", {"status": "ok", "created_at": "2026-11-05T00:00:00+00:00", "model": "ollama/llama3.2"}, [ASSESSMENT]
    )
    yield assessments
    set_ai_assessment_store(None)
    set_job_store(InMemoryJobStore())


def _rows(client: TestClient) -> list[dict]:
    response = client.get("/v1/findings")
    assert response.status_code == 200, response.text
    return response.json()["findings"]


def test_finding_reads_carry_the_advice_with_its_label_and_provenance(store) -> None:
    [row] = _rows(_client())
    advice = row["ai_assessment"]
    assert advice["verdict"] == "likely_false_positive"
    assert advice["advisory"] is True
    assert advice["confidence"] == "high"
    assert advice["rationale"] == "Installed 2.0.0 is at the fix."
    assert advice["provenance"]["model"] == "ollama/llama3.2"
    assert advice["provenance"]["model_digest"] == "sha256-abc"
    assert row["severity"] == "high", "AI advice sits beside scanner severity and never replaces it"


def test_another_tenant_never_sees_that_advice(store) -> None:
    [row] = _rows(_client("tenant-b"))
    assert row.get("ai_assessment") is None


def test_read_applies_the_hard_rule_to_a_finding_that_turned_kev(store) -> None:
    jobs = InMemoryJobStore()
    jobs.put(_job("tenant-a", is_kev=True))
    set_job_store(jobs)
    [row] = _rows(_client())
    assert row["ai_assessment"]["verdict"] == "confirmed"
    assert row["ai_assessment"]["guard_applied"] is True
    assert row["ai_assessment"]["protected_reasons"] == ["kev"]


def test_reads_never_call_a_model(store) -> None:
    with patch("agent_bom.ai_components.providers._call_llm", new=AsyncMock(side_effect=AssertionError("read called a model"))) as call:
        _rows(_client())
    call.assert_not_called()


def test_a_broken_assessment_store_never_breaks_the_findings_list(store) -> None:
    class Broken(InMemoryAIAssessmentStore):
        def latest_for_findings(self, tenant_id, finding_ids):
            raise RuntimeError("db down: postgres://user:pw@host")

    set_ai_assessment_store(Broken())
    response = _client().get("/v1/findings")
    assert response.status_code == 200
    assert response.json()["findings"][0]["severity"] == "high"
    assert any("AI advice" in warning for warning in response.json()["warnings"])
    assert "pw@host" not in response.text


@pytest.fixture()
def ai_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_AI_CONTROL_PLANE_ENABLED", "1")
    monkeypatch.setenv("AGENT_BOM_AI_CONTROL_PLANE_MODEL", "ollama/llama3.2")
    monkeypatch.setattr("agent_bom.ai_components.provider_discovery._detect_ollama", lambda: True)
    ai_explain_limits.reset_explain_limits()
    yield
    ai_explain_limits.reset_explain_limits()


def test_status_says_off_with_the_reason_by_default(store, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_AI_CONTROL_PLANE_ENABLED", raising=False)
    body = _client(role="viewer").get("/v1/ai/status").json()
    assert body["state"] == "off"
    assert "AGENT_BOM_AI_CONTROL_PLANE_ENABLED" in body["reason"]
    assert body["advisory_only"] is True


def test_status_reports_the_tenants_last_run_only(store, ai_on) -> None:
    body = _client().get("/v1/ai/status").json()
    assert body["state"] == "on"
    assert body["last_run"]["status"] == "ok"
    assert _client("tenant-b").get("/v1/ai/status").json()["last_run"] is None


def _graph(tenant: str = "tenant-a", label: str = "server s"):
    nodes = {
        "agent:a": UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent a"),
        "server:s": UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label=label),
    }
    edge = UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES)
    writes: list[str] = []

    class FakeGraph:
        def nodes_by_ids(self, *, scan_id, tenant_id, node_ids):
            return [nodes[item] for item in node_ids if tenant_id == tenant and item in nodes]

        def edges_for_node_ids(self, *, scan_id, tenant_id, node_ids):
            return [edge] if tenant_id == tenant else []

        def attack_paths_for_sources(self, *, scan_id, tenant_id, source_ids):
            return []

        def resolve_node_aliases(self, *, tenant_id="", node_ids, scan_id=""):
            return {}

        def __getattr__(self, name):
            writes.append(name)
            raise AssertionError(f"unexpected graph store call: {name}")

    return FakeGraph(), writes, edge


CLAIMS = json.dumps({"claims": [{"text": "The agent uses this server.", "citations": ["E1", "N1"]}, {"text": "Uncited.", "citations": []}]})


def _explain(client: TestClient, **body) -> object:
    return client.post("/v1/graph/explain", json={"node_ids": ["agent:a", "server:s"], "ordered": True, **body})


def test_explain_is_refused_while_ai_is_off(store, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_AI_CONTROL_PLANE_ENABLED", raising=False)
    with patch.object(ai_routes, "_call_explain", side_effect=AssertionError("must not run")):
        response = _explain(_client())
    assert response.status_code == 409
    assert response.json()["detail"]["state"] == "off"


def test_viewers_cannot_spend_model_budget(store, ai_on) -> None:
    assert _explain(_client(role="viewer")).status_code == 403


def test_explain_returns_cited_claims_and_strips_the_rest(store, ai_on) -> None:
    graph, writes, edge = _graph()
    with (
        patch.object(ai_routes, "_get_graph_store", return_value=graph),
        patch("agent_bom.ai_components.graph_explain._call_llm", new=AsyncMock(return_value=CLAIMS)),
    ):
        response = _explain(_client())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["advisory"] is True and body["label"] == "AI advice"
    assert [claim["text"] for claim in body["claims"]] == ["The agent uses this server."]
    assert {item["id"] for item in body["claims"][0]["citations"]} == {edge.id, "agent:a"}
    assert body["rejected_claims"] == {"uncited": 1}
    assert any("attack path" in limit for limit in body["evidence_limits"])
    assert writes == [], "explanation reads the graph and writes nothing"


def test_explain_cannot_read_another_tenants_nodes(store, ai_on) -> None:
    graph, _, _ = _graph(tenant="tenant-b")
    with (
        patch.object(ai_routes, "_get_graph_store", return_value=graph),
        patch("agent_bom.ai_components.graph_explain._call_llm", new=AsyncMock(side_effect=AssertionError("no model call"))),
    ):
        response = _explain(_client("tenant-a"))
    assert response.status_code == 404


def test_explain_is_rate_limited_per_tenant(store, ai_on, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_AI_EXPLAIN_PER_MINUTE", "1")
    graph, _, _ = _graph()
    graph_b, _, _ = _graph(tenant="tenant-b")
    with (
        patch.object(ai_routes, "_get_graph_store", return_value=graph),
        patch("agent_bom.ai_components.graph_explain._call_llm", new=AsyncMock(return_value=CLAIMS)),
    ):
        assert _explain(_client()).status_code == 200
        limited = _explain(_client())
    assert limited.status_code == 429
    assert limited.headers.get("Retry-After")
    with (
        patch.object(ai_routes, "_get_graph_store", return_value=graph_b),
        patch("agent_bom.ai_components.graph_explain._call_llm", new=AsyncMock(return_value=CLAIMS)),
    ):
        assert _explain(_client("tenant-b")).status_code == 200


def test_explain_daily_budget_is_per_tenant(store, ai_on, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_AI_EXPLAIN_PER_DAY", "1")
    graph, _, _ = _graph()
    with (
        patch.object(ai_routes, "_get_graph_store", return_value=graph),
        patch("agent_bom.ai_components.graph_explain._call_llm", new=AsyncMock(return_value=CLAIMS)),
    ):
        assert _explain(_client()).status_code == 200
        over = _explain(_client())
    assert over.status_code == 429
    assert "budget" in json.dumps(over.json()).lower()


def test_explain_bounds_its_input(store, ai_on) -> None:
    assert _client().post("/v1/graph/explain", json={"node_ids": []}).status_code == 422
    assert _client().post("/v1/graph/explain", json={"node_ids": [f"n{i}" for i in range(26)]}).status_code == 422
    assert _client().post("/v1/graph/explain", json={"node_ids": ["a"], "model": "openai/x"}).status_code == 422


def test_every_call_lands_in_the_audit_chain_without_prompt_text(store, ai_on) -> None:
    audit = InMemoryAuditLog()
    set_audit_log(audit)
    planted = "ghp_" + "K" * 36
    graph, _, _ = _graph(label=f"secret {planted} VERY-DISTINCTIVE-LABEL")
    client = SimpleNamespace(
        status_code=200,
        json=lambda: {"message": {"content": CLAIMS}, "prompt_eval_count": 5, "eval_count": 3, "models": []},
    )
    transport = AsyncMock()
    transport.__aenter__.return_value = transport
    transport.__aexit__.return_value = False
    transport.post.return_value = client
    transport.get.return_value = client
    with patch.object(ai_routes, "_get_graph_store", return_value=graph), patch("httpx.AsyncClient", return_value=transport):
        assert _explain(_client()).status_code == 200
    sent = json.dumps(transport.post.call_args.kwargs["json"])
    assert planted not in sent
    entries = [entry for entry in audit.list_entries(limit=50, tenant_id="tenant-a") if entry.action == "ai.call"]
    assert len(entries) == 1
    details = entries[0].details
    assert details["ai_task"] == "graph_explain" and details["ai_provider"] == "ollama" and details["ai_outcome"] == "ok"
    assert details["ai_model"] == "ollama/llama3.2"
    assert details["ai_prompt_tokens"] == 5 and details["ai_completion_tokens"] == 3
    assert details["tenant_id"] == "tenant-a"
    assert details["ai_guard_rejected"] is True
    assert len(details["ai_prompt_sha256"]) == 64 and len(details["ai_response_sha256"]) == 64
    assert "VERY-DISTINCTIVE-LABEL" not in json.dumps(details) and planted not in json.dumps(details)
    assert audit.verify_integrity(tenant_id="tenant-a")[1] == 0
    call_audit.reset_digest_cache()
