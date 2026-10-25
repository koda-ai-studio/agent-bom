"""Graph continuation contract: a cursor never combines with offset; a malformed cursor is a validation error."""

from __future__ import annotations

import base64

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


def _g1(payload: str) -> str:
    return "g1." + base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


JUNK_PAYLOADS = ["5", "null", '"ab"', '{"a": "b"}', '["a", "b", "c"]', "[1, 2]", '["gen", 7]', "[]", "true", '"x"']
MALFORMED_CURSORS = ["g1.@@@", "g1.WyJhIl0", "not-a-cursor", "g1.", *(_g1(payload) for payload in JUNK_PAYLOADS)]
MALFORMED_CURSOR_ROUTES = [
    ("/v1/graph", {}),
    ("/v1/graph/agents", {}),
    ("/v1/graph/search", {"q": "tenant"}),
    ("/v1/graph/attack-paths", {}),
    ("/v1/graph/attack-paths/cross-vendor", {}),
    ("/v1/graph/incident-edges", {"node_id": "principal:reader"}),
    ("/v1/graph/exposure-paths", {}),
    ("/v1/inventory/assets", {}),
]


@pytest.mark.parametrize("cursor", MALFORMED_CURSORS)
@pytest.mark.parametrize(("path", "params"), MALFORMED_CURSOR_ROUTES, ids=[p for p, _ in MALFORMED_CURSOR_ROUTES])
def test_malformed_cursor_is_a_validation_error_on_every_route(client, path, params, cursor):  # noqa: F811
    first = client.get(path, params={**params, "scan_id": "shared-scan", "limit": 1})
    assert first.status_code == 200, first.text
    generation = first.json().get("snapshot_generation") or ""
    response = client.get(path, params={**params, "scan_id": "shared-scan", "cursor": cursor, "snapshot_generation": generation})
    assert response.status_code == 422, response.text


@pytest.mark.parametrize("payload", JUNK_PAYLOADS)
@pytest.mark.parametrize(("path", "params"), MALFORMED_CURSOR_ROUTES, ids=[p for p, _ in MALFORMED_CURSOR_ROUTES])
def test_junk_cursor_payload_is_422_without_a_generation_or_scan(client, path, params, payload):  # noqa: F811
    response = client.get(path, params={**params, "cursor": _g1(payload), "limit": 1})
    assert response.status_code == 422, response.text
