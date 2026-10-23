"""One finding, one credential set: the graph story's held credentials are the scan's server credentials."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_demo_estate_bootstrap import VIEWER, demo_estate_client  # noqa: F401

CVE = "CVE-2020-14343"


def _agent_row(client: TestClient, agent: str) -> dict:
    detail = client.get(f"/v1/agents/{agent}", headers=VIEWER)
    assert detail.status_code == 200, detail.text
    rows = [row for row in detail.json().get("blast_radius") or [] if row.get("vulnerability_id") == CVE]
    assert rows, f"{agent} has no {CVE} blast radius row"
    return rows[0]


def test_story_credentials_are_the_credentials_affected_servers_hold(demo_estate_client: TestClient) -> None:  # noqa: F811
    story = demo_estate_client.get(
        "/v1/graph/exploit-story", params={"node": f"vuln:{CVE}", "package": "pkg:pypi:pyyaml@5.3"}, headers=VIEWER
    )
    assert story.status_code == 200, story.text
    groups = {group["kind"]: group for group in story.json()["at_risk"]["groups"]}
    story_credentials = {item["label"] for item in groups["credentials"]["items"]}
    assert groups["credentials"]["count"] == len(story_credentials) == 4

    held: set[str] = set()
    for agent in ("cursor", "data-pipeline"):
        row = _agent_row(demo_estate_client, agent)
        # The advisory carries no impact CWE, so the scan asserts no exposure;
        # the drawer and remediation plan label that count as impact-filtered.
        assert row["exposed_credentials"] == []
        assert row["impact_category"] == "unknown"
        held.update(row["all_server_credentials"])
    assert held == story_credentials
