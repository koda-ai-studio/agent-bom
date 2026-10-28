"""On the demo estate, "Am I affected by CVE-2023-4863?" covers every occurrence the findings list shows.

The KEV filter of ``/v1/findings`` lists one MCP-server occurrence and the
image package occurrences of the estate; the affected answer (REST and the
MCP tool share it) must name the same occurrences, images included, with the
severity the lookup and the findings rows carry.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

_CVE = "CVE-2023-4863"


def _kev_rows(client: TestClient) -> list[dict]:
    rows: list[dict] = []
    cursor: str | None = None
    for _ in range(10):
        params: dict[str, str] = {"kev": "true", "limit": "200"}
        if cursor:
            params["cursor"] = cursor
        body = client.get("/v1/findings", params=params).json()
        rows.extend(row for row in body["findings"] if (row.get("cve_id") or row.get("vulnerability_id")) == _CVE)
        cursor = body.get("next_cursor")
        if not cursor:
            break
    return rows


def test_kev_findings_and_affected_answer_name_the_same_occurrences(demo_estate_client: TestClient) -> None:
    kev_rows = _kev_rows(demo_estate_client)
    image_nodes = {row.get("node_id") or row["asset"].get("identifier") for row in kev_rows if row["asset"].get("asset_type") == "package"}
    assert len(kev_rows) > 1 and image_nodes, "the demo estate records image package occurrences of the KEV advisory"

    response = demo_estate_client.get(f"/v1/intel/advisories/{_CVE}/affected", params={"verdict": "affected", "limit": "200"})
    assert response.status_code == 200, response.text
    body = response.json()
    rows = body["rows"]
    assert not body["has_more"]
    assert body["summary"]["affected"] == len(kev_rows)
    assert {row["asset_node_id"] for row in rows if row["asset_type"] == "package"} == image_nodes
    assert sum(1 for row in rows if row["asset_type"] == "mcp_server") == sum(
        1 for row in kev_rows if row["asset"].get("asset_type") == "mcp_server"
    )
    assert body["summary"]["assets_examined"] >= len(kev_rows)
    assert body["coverage"]["unexamined_sections"] == []
    assert all(row["graph"]["package_node_id"] for row in rows)

    lookup = demo_estate_client.get(f"/v1/intel/advisories/{_CVE}").json()
    expected = {str(row.get("effective_severity") or row.get("severity")) for row in kev_rows}
    assert expected == {"high"}
    if lookup.get("found"):
        assert body["advisory"]["severity"] == lookup["advisory"]["severity"]
    assert body["advisory"]["severity"] == "high"
