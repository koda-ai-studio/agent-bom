"""The three agent counts the UI shows, read off one seeded snapshot.

Overview's Agents tile reads ``by_type.agent`` on ``/v1/inventory/summary``; the
Agents page reads ``/v1/agents`` and shows ``agents.total`` from
``/v1/posture/counts`` beside it; Asset inventory's AI entities card sums agent,
model, framework and dataset records. They count different populations, so the
test pins which number is which: the two snapshot numbers agree exactly, the
Agents page population is labelled and never larger than the snapshot's agent
records, and the card is a superset that is never the agent count alone.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests._demo_estate_fixtures import VIEWER

AI_ENTITY_TYPES = ("agent", "model", "framework", "dataset")


def _get(client: TestClient, path: str) -> dict:
    response = client.get(path, headers=VIEWER)
    assert response.status_code == 200, (path, response.text)
    return response.json()


def test_agent_counts_agree_or_carry_their_population(shared_demo_estate_client: TestClient) -> None:
    summary = _get(shared_demo_estate_client, "/v1/inventory/summary")
    posture = _get(shared_demo_estate_client, "/v1/posture/counts")
    agents = _get(shared_demo_estate_client, "/v1/agents")

    snapshot_agents = int(summary["by_type"].get("agent") or 0)
    assert snapshot_agents > 0

    # Overview tile and the Agents page's "agent records in snapshot" caption are one number.
    assert posture["agents"]["basis"] == "graph_agents"
    assert posture["agents"]["total"] == snapshot_agents
    assert posture["agents"]["scan_id"] == summary["scan_id"]

    # The Agents page's own population is named, and is a subset of the snapshot's agent records.
    assert agents["scope"] in {"local_discovery", "scanned_estate"}
    assert agents["count"] == agents["summary"]["agents"] == len(agents["agents"])
    assert agents["count"] <= snapshot_agents

    # The AI entities card counts more than agents; it must not be read as an agent count.
    card_total = sum(int(summary["by_type"].get(kind) or 0) for kind in AI_ENTITY_TYPES)
    assert card_total >= snapshot_agents
    assert card_total > snapshot_agents, "fixture should exercise models/frameworks/datasets beside agents"
