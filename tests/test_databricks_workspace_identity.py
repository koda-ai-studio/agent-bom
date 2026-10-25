"""OAuth profiles and injected clients retain their actual workspace scope."""

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.cloud.databricks import discover
from agent_bom.cloud.databricks_security import _check_1_1, run_security_checks


@pytest.fixture
def workspace(monkeypatch):
    client = SimpleNamespace(
        config=SimpleNamespace(host="https://one.cloud.databricks.com"),
        clusters=SimpleNamespace(list=lambda: []),
        serving_endpoints=SimpleNamespace(list=lambda: [SimpleNamespace(name="shared-endpoint", state=SimpleNamespace(ready="READY"))]),
    )
    sdk, errors = ModuleType("databricks.sdk"), ModuleType("databricks.sdk.errors")
    sdk.WorkspaceClient = Mock(return_value=client)
    errors.PermissionDenied = type("PermissionDenied", (Exception,), {})
    monkeypatch.setitem(sys.modules, "databricks.sdk", sdk)
    monkeypatch.setitem(sys.modules, "databricks.sdk.errors", errors)
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    return client


def test_oauth_profile_origin_reaches_inventory_and_security_report(workspace):
    agents, warnings = discover()
    assert warnings == []
    assert agents[0].config_path.startswith(workspace.config.host + "/")
    assert agents[0].metadata["cloud_origin"]["scope"]["project_id"] == workspace.config.host
    assert run_security_checks(checks=[]).workspace_host == workspace.config.host


def test_same_endpoint_names_in_different_workspaces_keep_distinct_identities(workspace):
    first = discover(workspace_client=workspace)[0][0]
    workspace.config.host = "https://two.cloud.databricks.com"
    second = discover(workspace_client=workspace)[0][0]
    assert first.stable_id != second.stable_id
    assert first.metadata["cloud_origin"]["scope"] != second.metadata["cloud_origin"]["scope"]


def test_injected_client_scope_wins_over_unrelated_ambient_host(workspace, monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", "https://unrelated.cloud.databricks.com")
    assert discover(workspace_client=workspace)[0][0].config_path.startswith(workspace.config.host + "/")
    assert run_security_checks(workspace_client=workspace, checks=[]).workspace_host == workspace.config.host


def test_workspace_admin_group_members_are_counted(workspace):
    workspace.users = SimpleNamespace(
        list=Mock(
            return_value=[
                SimpleNamespace(id=str(i), user_name="fixture-" + str(i), roles=[], groups=[SimpleNamespace(display="admins")])
                for i in range(4)
            ]
        )
    )
    result = _check_1_1(workspace)
    assert result.status.value == "fail"
    assert "4 admin users" in result.evidence
    assert "groups" in workspace.users.list.call_args.kwargs["attributes"]


def test_sdk_cluster_state_retains_cluster_inventory(workspace):
    from enum import Enum

    class State(Enum):
        RUNNING = "RUNNING"

    workspace.clusters.list = lambda: [SimpleNamespace(cluster_id="fixture", cluster_name="fixture", state=State.RUNNING)]
    workspace.libraries = SimpleNamespace(
        cluster_status=lambda **kwargs: SimpleNamespace(
            library_statuses=[SimpleNamespace(library=SimpleNamespace(pypi=SimpleNamespace(package="example==1.0")))]
        )
    )
    agents, warnings = discover(workspace_client=workspace)
    assert not warnings
    cluster = next(agent for agent in agents if agent.name.startswith("databricks-cluster:"))
    assert cluster.metadata["cloud_origin"]["scope"]["project_id"] == workspace.config.host
    assert cluster.mcp_servers[0].packages[0].version == "1.0"
