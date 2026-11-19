"""Malformed Nebius compute records must not discard independent inventory."""

from types import SimpleNamespace

import httpx
import pytest

from agent_bom.cloud import nebius


def _instance(name):
    return {"id": name, "name": name, "resources": {"gpus": 1}, "boot_disk": {"image_name": "pytorch-fixture"}}


@pytest.mark.parametrize(
    "invalid",
    [
        {"resources": None},
        {"resources": {"gpus": "invalid"}},
        {"platform_id": None, "resources": {"gpus": 0}},
        {"boot_disk": None},
        {"boot_disk": {"image_name": None}},
        {"name": {"private-marker": "invalid"}},
    ],
)
@pytest.mark.parametrize("position", [0, 1])
def test_malformed_instance_keeps_valid_neighbors_and_partial_scope(monkeypatch, invalid, position):
    from agent_bom.cli.agents.scan_pipeline.report import _collect_cloud_scopes

    records = [_instance("first"), _instance("last")]
    records.insert(position, {**_instance("private-marker"), **invalid})
    response = httpx.Response(200, json={"instances": records}, request=httpx.Request("GET", "https://example.test"))
    monkeypatch.setattr(nebius.http_client, "sync_request_with_retry", lambda *a, **kw: response)
    agents, warnings = nebius._discover_gpu_instances("fixture", "fixture-project")
    assert [a.name for a in agents] == ["nebius-gpu:first", "nebius-gpu:last"]
    assert all(a.metadata["gpu_count"] == 1 and a.metadata["ai_workload"] for a in agents)
    assert all(a.mcp_servers[0].packages[0].name == "pytorch-fixture" for a in agents)
    assert len(warnings) == 1
    assert warnings[0].startswith("nebius:instances:unavailable:")
    assert "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]
    state = SimpleNamespace(
        ctx=SimpleNamespace(
            cloud_provider_successes=[{"provider": "nebius", "item_count": len(agents)}],
            cloud_provider_warnings=[{"provider": "nebius", "warning": warning} for warning in warnings],
            cloud_provider_failures=[],
        )
    )
    _collect_cloud_scopes(SimpleNamespace(), state)
    assert state.cloud_scopes[0].status.value == "partial"
    assert state.cloud_scopes[0].item_count == 2


@pytest.mark.parametrize("records", [[], [{"id": "cpu", "resources": {"gpus": 0}}], [_instance("gpu")]])
def test_valid_inventory_does_not_report_record_failure(monkeypatch, records):
    response = httpx.Response(200, json={"instances": records}, request=httpx.Request("GET", "https://example.test"))
    monkeypatch.setattr(nebius.http_client, "sync_request_with_retry", lambda *a, **kw: response)
    agents, warnings = nebius._discover_gpu_instances("fixture", "fixture-project")
    assert [a.name for a in agents] == (["nebius-gpu:gpu"] if records and records[0]["id"] == "gpu" else [])
    assert warnings == []
