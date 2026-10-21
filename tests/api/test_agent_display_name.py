"""Agent routes and the MCP inventory carry the one display name the UI shows.

The rule lives in ``agent_bom.display_names`` and in ``ui/lib/display-name.ts``;
both read the same case table so the two cannot drift.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.display_names import agent_display_name
from tests._clock_helpers import recent

_CASES = json.loads((Path(__file__).parents[1] / "fixtures" / "contracts" / "agent_display_names.json").read_text())["cases"]


@pytest.mark.parametrize("case", _CASES, ids=lambda case: f"{case['id']!r}/{case['recorded']!r}")
def test_backend_rule_matches_the_shared_case_table(case: dict) -> None:
    assert agent_display_name(case["id"], case["recorded"]) == case["expected"]


def _estate_agent(name: str, canonical_id: str, **extra: str) -> dict:
    return {
        "name": name,
        "agent_type": "custom",
        "config_path": f"/work/{name}",
        "source": "project",
        "canonical_id": canonical_id,
        "stable_id": canonical_id,
        "mcp_servers": [],
        **extra,
    }


@pytest.fixture()
def estate(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", raising=False)
    discovery._clear_agents_response_cache_for_tests()
    store = InMemoryJobStore()
    set_job_store(store)
    store.put(
        ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id="default",
            status=JobStatus.DONE,
            created_at=recent("2026-07-01T00:00:00Z"),
            completed_at=recent("2026-07-01T00:01:00Z"),
            request=ScanRequest(offline=True),
            result={
                "agents": [
                    _estate_agent("langchain-service", "agent-a"),
                    _estate_agent("laptop-7f3a", "agent-b", enrollment_name="Finance laptops"),
                ],
                "blast_radius": [],
            },
        )
    )
    yield store
    discovery._clear_agents_response_cache_for_tests()


def test_agents_list_and_detail_name_each_agent_once(estate) -> None:
    client = TestClient(app)
    listed = {agent["canonical_id"]: agent["display_name"] for agent in client.get("/v1/agents").json()["agents"]}

    assert listed == {"agent-a": "LangChain Service", "agent-b": "Finance laptops"}
    for canonical_id, name in listed.items():
        assert client.get(f"/v1/agents/{canonical_id}").json()["agent"]["display_name"] == name


def test_host_discovery_agents_carry_the_display_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    discovery._clear_agents_response_cache_for_tests()
    set_job_store(InMemoryJobStore())
    client = TestClient(app)
    agents = client.get("/v1/agents?refresh=true").json()["agents"]

    assert agents
    for agent in agents:
        assert agent["display_name"] == agent_display_name(agent["name"], agent.get("enrollment_name"))
        detail = client.get(f"/v1/agents/{agent['canonical_id']}").json()
        assert detail["agent"]["display_name"] == agent["display_name"]
    discovery._clear_agents_response_cache_for_tests()


def test_mcp_inventory_agent_rows_carry_the_display_name() -> None:
    from types import SimpleNamespace

    from agent_bom.api.inventory_service import asset_row
    from agent_bom.graph import EntityType, NodeDimensions, NodeStatus

    def node(entity_type: EntityType, label: str, **attributes: str) -> SimpleNamespace:
        return SimpleNamespace(
            id=f"{entity_type.value}:{label}",
            entity_type=entity_type,
            label=label,
            dimensions=NodeDimensions(),
            attributes=attributes,
            data_sources=["scan"],
            risk_score=0.0,
            risk_assessment={},
            severity="",
            status=NodeStatus.ACTIVE,
            first_seen="",
            last_seen="",
            compliance_tags=[],
        )

    assert asset_row(node(EntityType.AGENT, "support-copilot"))["display_name"] == "Support Copilot"
    assert asset_row(node(EntityType.AGENT, "laptop-7f3a", display_name="Finance laptops"))["display_name"] == "Finance laptops"
    assert "display_name" not in asset_row(node(EntityType.PACKAGE, "requests"))
