"""A graph read addressed to an unknown scan_id is 404, never an empty page marked complete."""

from __future__ import annotations

import asyncio
import json

import pytest

from tests.test_current_estate_seeding_refusal import NODE, TENANT, client  # noqa: F401

UNKNOWN_SCAN_READS = [
    ("GET", "/v1/graph", {}, None),
    ("GET", "/v1/graph/agents", {}, None),
    ("GET", "/v1/graph/attack-paths", {}, None),
    ("GET", "/v1/graph/attack-paths/cross-vendor", {}, None),
    ("GET", "/v1/graph/clusters", {}, None),
    ("GET", "/v1/graph/exposure-paths", {}, None),
    ("GET", "/v1/graph/governance", {}, None),
    ("GET", "/v1/graph/incident-edges", {"node_id": NODE}, None),
    ("GET", "/v1/graph/nhi/governance", {}, None),
    ("GET", "/v1/graph/node-neighbors", {"node_id": NODE}, None),
    ("GET", f"/v1/graph/node/{NODE}/neighbors", {}, None),
    ("GET", "/v1/graph/rollup", {}, None),
    ("GET", "/v1/graph/scoped", {"scope": "estate"}, None),
    ("GET", "/v1/graph/views/fix-first", {}, None),
    ("GET", "/v1/graph/compliance", {}, None),
    ("GET", "/v1/graph/search", {"q": "reader"}, None),
    ("POST", "/v1/graph/should-i-deploy", {}, {"candidate": NODE}),
]


def _call(client, method, path, params, body, scan_id):  # noqa: F811
    if body is None:
        return client.request(method, path, params={**params, "scan_id": scan_id})
    return client.request(method, path, params=params, json={**body, "scan_id": scan_id})


@pytest.mark.parametrize(("method", "path", "params", "body"), UNKNOWN_SCAN_READS, ids=[f"{m} {p}" for m, p, _, _ in UNKNOWN_SCAN_READS])
def test_unknown_scan_id_is_not_found(client, method, path, params, body):  # noqa: F811
    missing = _call(client, method, path, params, body, "nope")
    assert missing.status_code == 404, missing.text

    recorded = _call(client, method, path, params, body, "shared-scan")
    assert recorded.status_code == 200, recorded.text


def test_scan_alias_is_checked_like_scan_id(client):  # noqa: F811
    assert client.get("/v1/graph", params={"scan": "nope"}).status_code == 404


def test_mcp_exposure_paths_reports_an_unknown_snapshot(client, monkeypatch):  # noqa: F811
    from agent_bom.mcp_server import _execute_tool_async
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    raw = asyncio.run(_execute_tool_async("exposure_paths", exposure_paths_impl, scan_id="nope", _truncate_response=lambda v: v))
    payload = json.loads(str(raw))
    assert payload["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE", payload
