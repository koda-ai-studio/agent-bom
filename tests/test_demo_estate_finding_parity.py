"""The demo estate's graph findings and its finding rows are one set.

The roll-up counts finding nodes in the graph; the overview, posture counts and
the findings list count finding rows in the store. A seed that writes a finding
to only one of them makes the two headline numbers disagree, so both directions
are asserted: the roll-up's issue histogram equals ``/v1/posture/counts``
``issues`` exactly, and no finding row names a graph node that does not exist.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT
from tests._demo_estate_fixtures import VIEWER

_BANDS = ("critical", "high", "medium", "low")


def _all_findings(client: TestClient) -> list[dict]:
    rows: list[dict] = []
    cursor: str | None = None
    while True:
        params: dict[str, object] = {"limit": 500}
        if cursor:
            params["cursor"] = cursor
        page = client.get("/v1/findings", headers=VIEWER, params=params)
        assert page.status_code == 200, page.text
        body = page.json()
        rows.extend(body.get("findings") or [])
        cursor = body.get("next_cursor")
        if not cursor:
            return rows


def _graph_node_ids() -> set[str]:
    from agent_bom.api.stores import _get_graph_store

    return set(_get_graph_store().load_graph(tenant_id=SHOWCASE_TENANT).nodes)


def test_rollup_issue_counts_equal_posture_issue_counts(shared_demo_estate_client: TestClient) -> None:
    counts = shared_demo_estate_client.get("/v1/posture/counts", headers=VIEWER)
    rollup = shared_demo_estate_client.get("/v1/graph/rollup", headers=VIEWER)
    assert counts.status_code == rollup.status_code == 200, (counts.text, rollup.text)
    issues = counts.json()["issues"]
    summary = rollup.json()["summary"]
    rolled = summary["issue_severity_counts"]
    assert {band: int(rolled.get(band, 0)) for band in _BANDS} == {band: int(issues[band]) for band in _BANDS}
    assert summary["issue_count"] == issues["total"]


def test_every_finding_row_points_at_existing_graph_nodes(shared_demo_estate_client: TestClient) -> None:
    """Both joins: the finding's own node and the asset node it is drawn on."""
    rows = _all_findings(shared_demo_estate_client)
    assert rows
    nodes = _graph_node_ids()
    for field in ("finding_node_id", "node_id"):
        missing = sorted({str(row.get(field)) for row in rows if row.get(field) not in nodes})
        assert missing == [], f"{len(missing)} finding rows carry a {field} the graph does not have: {missing[:10]}"


def test_every_graph_finding_node_has_a_finding_row(shared_demo_estate_client: TestClient) -> None:
    from agent_bom.api.stores import _get_graph_store
    from agent_bom.graph.severity_floor import counts_as_finding_node

    graph = _get_graph_store().load_graph(tenant_id=SHOWCASE_TENANT)
    claimed = {row.get("finding_node_id") for row in _all_findings(shared_demo_estate_client)}
    unreported = sorted(node_id for node_id, node in graph.nodes.items() if counts_as_finding_node(node) and node_id not in claimed)
    assert unreported == [], f"{len(unreported)} graph finding nodes have no finding row: {unreported[:10]}"
