"""Graph continuation contract: a cursor never combines with offset; a malformed cursor is a validation error."""

from __future__ import annotations

import pytest

from tests.test_current_estate_seeding_refusal import client  # noqa: F401

CURSOR_AND_OFFSET_ROUTES = [
    ("/v1/graph", {}),
    ("/v1/graph/agents", {}),
    ("/v1/graph/search", {"q": "tenant"}),
    ("/v1/graph/attack-paths", {}),
    ("/v1/graph/attack-paths/cross-vendor", {}),
    ("/v1/inventory/assets", {}),
]


def test_graph_cursor_with_offset_is_rejected_not_echoed(client):  # noqa: F811
    first = client.get("/v1/graph", params={"limit": 1, "scan_id": "shared-scan"})
    assert first.status_code == 200, first.text
    cursor = first.json()["pagination"]["next_cursor"]
    assert cursor

    combined = client.get("/v1/graph", params={"limit": 1, "scan_id": "shared-scan", "cursor": cursor, "offset": 2})
    assert combined.status_code == 400, combined.text
    assert "offset" in combined.text

    alone = client.get("/v1/graph", params={"limit": 1, "scan_id": "shared-scan", "cursor": cursor})
    assert alone.status_code == 200, alone.text
    assert alone.json()["pagination"]["offset"] != 2


@pytest.mark.parametrize(("path", "params"), CURSOR_AND_OFFSET_ROUTES, ids=[p for p, _ in CURSOR_AND_OFFSET_ROUTES])
def test_every_cursor_route_rejects_an_offset_beside_the_cursor(client, path, params):  # noqa: F811
    response = client.get(path, params={**params, "cursor": "g1.AAAA", "offset": 2})
    assert response.status_code == 400, response.text
