"""Databricks model-serving endpoints and cluster libraries are AI inventory, never unauthenticated MCP servers."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.cloud.databricks import _serving_endpoint_agent
from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture


def _endpoint(name: str):
    return SimpleNamespace(name=name, state=SimpleNamespace(ready=SimpleNamespace(value="READY")), config=None, tags=None)


def test_serving_endpoints_are_inventory_not_mcp_surfaces() -> None:
    agent = _serving_endpoint_agent(_endpoint("databricks-meta-llama-3-3-70b-instruct"), "https://dbc-example.cloud.databricks.com")
    assert agent is not None
    (server,) = agent.mcp_servers
    assert not server.is_mcp_surface
    assert evaluate_mcp_auth_posture([agent]) == []


def test_audit_log_delivery_without_account_api_is_no_data_not_a_critical_error() -> None:
    from agent_bom.cloud.aws_cis._base import CheckStatus
    from agent_bom.cloud.databricks_security import _check_4_1

    result = _check_4_1(SimpleNamespace())
    assert result.status == CheckStatus.NO_DATA
    assert "account-level" in result.evidence


def test_best_practice_findings_carry_their_workspace() -> None:
    from agent_bom.models import AIBOMReport

    def report(host: str):
        failing = {"check_id": "1.3", "title": "PAT lifetime", "status": "FAIL", "severity": "medium", "evidence": "730 days"}
        return AIBOMReport(agents=[], databricks_security_data={"workspace_host": host, "checks": [failing]})

    (a,) = [f for f in report("https://dbc-a.cloud.databricks.com").to_findings() if f.source.value == "CLOUD_SECURITY"]
    (b,) = [f for f in report("https://dbc-b.cloud.databricks.com").to_findings() if f.source.value == "CLOUD_SECURITY"]
    assert a.asset.account_ref and b.asset.account_ref
    assert a.asset.account_ref != b.asset.account_ref
    assert a.id != b.id
