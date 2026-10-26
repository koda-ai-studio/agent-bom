"""GPU compute in managed data platforms: Snowflake SPCS compute pools and Databricks GPU clusters."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "gpu_infra"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


# ── Snowflake SPCS ───────────────────────────────────────────────────────────


class _Cursor:
    def __init__(self, recorded: dict[str, Any]) -> None:
        self.recorded = recorded
        self.description: list[tuple[str]] | None = None
        self._rows: list[Any] = []

    def execute(self, sql: str, *_args: Any, **_kwargs: Any) -> None:
        if " ".join(sql.split()) == "SHOW COMPUTE POOLS":
            self.description = [(c,) for c in self.recorded["columns"]]
            self._rows = [tuple(r) for r in self.recorded["rows"]]
        else:
            self.description, self._rows = [], []

    def fetchall(self) -> list[Any]:
        return self._rows

    def close(self) -> None:
        pass


class _Conn:
    def __init__(self, recorded: dict[str, Any]) -> None:
        self.recorded = recorded

    def cursor(self) -> _Cursor:
        return _Cursor(self.recorded)

    def close(self) -> None:
        pass


@pytest.fixture
def snowflake_services(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setitem(sys.modules, "snowflake", sys.modules.get("snowflake") or types.ModuleType("snowflake"))
    monkeypatch.setitem(
        sys.modules, "snowflake.connector", sys.modules.get("snowflake.connector") or types.ModuleType("snowflake.connector")
    )
    from agent_bom.cloud import snowflake as sf

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _Conn(_load("snowflake_show_compute_pools.json")))
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    return sf.discover_snowflake_services()


def test_spcs_compute_pools_are_inventoried_with_gpu_family(snowflake_services: dict[str, Any]) -> None:
    pools = {p["name"]: p for p in snowflake_services["compute_pools"]}
    assert set(pools) == {"LLM_GPU_POOL", "APP_CPU_POOL", "EMBED_GPU_POOL"}
    llm = pools["LLM_GPU_POOL"]
    assert (llm["gpu"], llm["gpu_vendor"], llm["accelerator_type"], llm["accelerators_per_node"]) == (True, "nvidia", "A10G", 4)
    assert (llm["instance_family"], llm["min_nodes"], llm["max_nodes"], llm["num_services"]) == ("GPU_NV_M", 1, 2, 3)
    assert llm["owner"] == "ML_ENGINEER" and llm["auto_suspend_secs"] == 0
    assert llm["gpu_driver"] == {"management": "provider-managed", "setting": "snowflake-managed"}
    assert pools["APP_CPU_POOL"]["gpu"] is False


# ── Databricks ───────────────────────────────────────────────────────────────


def _ns(value: Any) -> Any:
    if isinstance(value, dict):
        return types.SimpleNamespace(**{k: _ns(v) for k, v in value.items()})
    if isinstance(value, list):
        return [_ns(v) for v in value]
    return value


class _Clusters:
    def __init__(self, recorded: dict[str, Any]) -> None:
        self.recorded = recorded

    def list(self) -> list[Any]:
        return _ns(self.recorded["clusters"])

    def list_node_types(self) -> Any:
        return _ns({"node_types": self.recorded["node_types"]})


class _Libraries:
    def cluster_status(self, cluster_id: str) -> Any:
        if cluster_id == "0901-120000-cpuetl":
            return _ns({"library_statuses": [{"library": {"pypi": {"package": "langchain==0.2.0"}}}]})
        return _ns({"library_statuses": []})


class _Workspace:
    def __init__(self) -> None:
        self.clusters = _Clusters(_load("databricks_clusters.json"))
        self.libraries = _Libraries()
        self.serving_endpoints = types.SimpleNamespace(list=lambda: [])


@pytest.fixture
def databricks_agents(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    sdk = types.ModuleType("databricks.sdk")
    errors = types.ModuleType("databricks.sdk.errors")
    errors.PermissionDenied = type("PermissionDenied", (Exception,), {})  # type: ignore[attr-defined]
    sdk.WorkspaceClient = lambda **_k: _Workspace()  # type: ignore[attr-defined]
    sdk.errors = errors  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "databricks", types.ModuleType("databricks"))
    monkeypatch.setitem(sys.modules, "databricks.sdk", sdk)
    monkeypatch.setitem(sys.modules, "databricks.sdk.errors", errors)
    from agent_bom.cloud import databricks

    agents, warnings = databricks.discover(host="https://dbc-example.cloud.databricks.com", workspace_client=_Workspace())
    assert warnings == []
    return agents


def test_databricks_gpu_clusters_are_inventoried_even_without_libraries(databricks_agents: list[Any]) -> None:
    by_name = {a.name: a for a in databricks_agents}
    assert set(by_name) == {"databricks-cluster:shared-gpu-training", "databricks-cluster:alice-gpu", "databricks-cluster:etl"}
    gpu = by_name["databricks-cluster:shared-gpu-training"].metadata["gpu_compute"]
    assert (gpu["gpu"], gpu["gpu_vendor"], gpu["accelerator_type"], gpu["accelerators_per_node"]) == (True, "nvidia", "A10G", 4)
    assert gpu["data_security_mode"] == "NONE"
    assert gpu["gpu_sharing"] == {"strategy": "multi-user-no-isolation"}
    assert gpu["gpu_runtime"] is True
    assert by_name["databricks-cluster:shared-gpu-training"].metadata["cloud_origin"]["scope"]["gpu"] is True
    private = by_name["databricks-cluster:alice-gpu"].metadata["gpu_compute"]
    assert private["gpu_sharing"] == {"strategy": "single-user"}
    assert "gpu_compute" not in by_name["databricks-cluster:etl"].metadata
