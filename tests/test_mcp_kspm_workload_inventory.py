"""kspm_workload_inventory MCP tool: the same inventory the CLI and API scans record."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

import agent_bom.mcp_tools.kspm as kspm_tool
from agent_bom.k8s_inventory import build_k8s_inventory


def _inventory(workloads: int) -> dict[str, Any]:
    spec = {"template": {"spec": {"containers": [{"name": "a", "image": "busybox:1.36"}]}}}
    objects = [{"kind": "Deployment", "metadata": {"name": f"w{i}", "namespace": "shop"}, "spec": spec} for i in range(workloads)]
    inventory = build_k8s_inventory(objects, source="live", cluster="prod-east")
    collector = {"collector_id": "roles", "state": "unevaluable", "object_count": 0, "truncated": False, "message": "forbidden"}
    inventory["collection"] = {"status": "partial", "collectors": [collector]}
    return inventory


def _call(monkeypatch: pytest.MonkeyPatch, inventory: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    monkeypatch.setattr(kspm_tool, "_collect_inventory", lambda **_kw: inventory)
    raw = asyncio.run(kspm_tool.kspm_workload_inventory_impl(_truncate_response=lambda s: s, **kwargs))
    return json.loads(raw)


def test_tool_returns_inventory_with_collector_state(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _call(monkeypatch, _inventory(2))
    assert data["schema_version"] == "kspm.workload.inventory.v1"
    assert data["status"] == "partial"
    assert data["collectors"][0]["state"] == "unevaluable"
    assert data["summary"]["workloads"] == 2
    assert [w["name"] for w in data["workloads"]["items"]] == ["w0", "w1"]
    assert data["workloads"]["truncated"] is False


def test_tool_bounds_lists_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _call(monkeypatch, _inventory(5), max_items=2)
    assert len(data["workloads"]["items"]) == 2
    assert (data["workloads"]["total"], data["workloads"]["truncated"]) == (5, True)


def test_tool_error_is_sanitized_json(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_kw: Any) -> dict:
        raise RuntimeError("kubectl not available")

    monkeypatch.setattr(kspm_tool, "_collect_inventory", boom)
    data = json.loads(asyncio.run(kspm_tool.kspm_workload_inventory_impl(_truncate_response=lambda s: s)))
    assert "error" in data
