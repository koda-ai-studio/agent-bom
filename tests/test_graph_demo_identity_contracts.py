"""Identity contracts over one seeded demo estate: diffs, exports and path ids join on canonical ids."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_SCAN_ID
from tests._demo_estate_fixtures import VIEWER


def _diff_nodes(client: TestClient, change: str) -> list[dict]:
    rows: list[dict] = []
    cursor = None
    while True:
        params = {"old": SHOWCASE_BASELINE_SCAN_ID, "new": "showcase", "view": "detail", "kind": "node", "change": change, "limit": 200}
        if cursor:
            params["cursor"] = cursor
        response = client.get("/v1/graph/diff", headers=VIEWER, params=params)
        assert response.status_code == 200, response.text
        payload = response.json()
        rows.extend(payload["items"])
        cursor = payload["pagination"]["next_cursor"]
        if not cursor:
            return rows


def test_showcase_diff_never_reports_a_renamed_node_as_removed(shared_demo_estate_client: TestClient) -> None:
    removed = _diff_nodes(shared_demo_estate_client, "removed")
    added = {row["id"] for row in _diff_nodes(shared_demo_estate_client, "added")}
    # The showcase re-keys 12 EC2 instances; each old id is an alias of its new node.
    assert len(removed) == 3
    for row in removed:
        lookup = shared_demo_estate_client.get(
            "/v1/graph/node-context", headers=VIEWER, params={"node_id": row["id"], "scan_id": "showcase"}
        )
        body = lookup.json() if lookup.status_code == 200 else {}
        assert body.get("resolved_from") != row["id"], f"{row['id']} is an alias of a showcase node yet reported removed"
    assert not {row["id"] for row in removed} & added
