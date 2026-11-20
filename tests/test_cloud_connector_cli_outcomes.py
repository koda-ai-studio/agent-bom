"""End to end: connector outcomes reach the JSON report scope and the exit code.

Successful empty inventory is complete (exit 0); a partial collection keeps
its assets but is partial (exit 1); a collector that returned nothing but
warnings is unavailable (exit 1). Providers are stubbed at their per-service
collectors, so each connector's own aggregation still runs.
"""

from __future__ import annotations

import json
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, MCPServer, TransportType

DENIED = "{p}:{r}:denied: Check credentials and read permissions. Assessment incomplete."


def _agent(provider: str) -> Agent:
    return Agent(
        name=f"{provider}-fixture:one",
        agent_type=AgentType.CUSTOM,
        config_path=f"{provider}://fixture/one",
        source=f"{provider}-fixture",
        mcp_servers=[MCPServer(name="fixture", transport=TransportType.UNKNOWN)],
    )


def _stage(provider: str, kind: str, resource: str = "fixture"):
    def run(*_args, **_kwargs):
        if kind == "ok":
            return [_agent(provider)], []
        if kind == "warn":
            return [], [DENIED.format(p=provider, r=resource)]
        return [], []

    return run


MODES = {
    "empty": ("empty", "empty"),
    "partial": ("ok", "warn"),
    "allfail": ("warn", "warn"),
}


def _install_nebius(monkeypatch, first: str, rest: str) -> list[str]:
    from agent_bom.cloud import nebius

    stages = [
        "_discover_ai_studio",
        "_discover_gpu_instances",
        "_discover_k8s_gpu_pods",
        "_discover_container_services",
        "_discover_infiniband_jobs",
    ]
    for index, name in enumerate(stages):
        monkeypatch.setattr(nebius, name, _stage("nebius", first if index == 0 else rest, name))
    return ["--nebius", "--nebius-api-key", "fixture-key", "--nebius-project-id", "fixture-project"]


def _install_aws(monkeypatch, first: str, rest: str) -> list[str]:
    pytest.importorskip("boto3")
    from agent_bom.cloud import aws

    session = MagicMock()
    session.region_name = "us-east-1"
    monkeypatch.setattr("boto3.Session", MagicMock(return_value=session))
    monkeypatch.setattr(aws, "_resolve_account_id", lambda _session: None)
    monkeypatch.setattr(aws, "_discover_bedrock", _stage("aws", first, "bedrock-agents"))
    monkeypatch.setattr(aws, "_discover_lambda_functions", _stage("aws", rest, "lambda"))

    def ecs(*_args, **_kwargs):
        return [], ([DENIED.format(p="aws", r="ecs-clusters")] if rest == "warn" else [])

    monkeypatch.setattr(aws, "_discover_ecs_images", ecs)
    return ["--aws", "--aws-region", "us-east-1"]


def _install_azure(monkeypatch, first: str, rest: str) -> list[str]:
    from agent_bom.cloud import azure

    identity = ModuleType("azure.identity")
    identity.DefaultAzureCredential = lambda *a, **k: object()
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    stages = [
        "_discover_container_apps",
        "_discover_ai_foundry",
        "_discover_openai_deployments",
        "_discover_azure_functions",
        "_discover_container_instances",
        "_discover_ml_endpoints",
    ]
    for index, name in enumerate(stages):
        monkeypatch.setattr(azure, name, _stage("azure", first if index == 0 else rest, name))
    return ["--azure", "--azure-subscription", "fixture-subscription"]


INSTALLERS = {"nebius": _install_nebius, "aws": _install_aws, "azure": _install_azure}


@pytest.mark.parametrize("provider", sorted(INSTALLERS))
@pytest.mark.parametrize(
    "mode,status,exit_code,items",
    [("empty", "complete", 0, 0), ("partial", "partial", 1, 1), ("allfail", "unavailable", 1, None)],
)
def test_connector_outcome_reaches_report_and_exit_code(monkeypatch, tmp_path, provider, mode, status, exit_code, items):
    flags = INSTALLERS[provider](monkeypatch, *MODES[mode])
    out = tmp_path / "report.json"
    args = ["agents", *flags, "--no-scan", "--offline", "--no-auto-update-db", "-f", "json", "-o", str(out), "-q"]
    result = CliRunner().invoke(main, args, catch_exceptions=False)

    report = json.loads(out.read_text())
    scopes = {scope["name"]: scope for scope in report["scan_run"]["scopes"]}
    scope = scopes[f"cloud:{provider}"]
    assert scope["status"] == status, scope
    assert scope["item_count"] == items
    assert result.exit_code == exit_code, result.output
    agent_names = [agent["name"] for agent in report.get("agents", [])]
    assert (f"{provider}-fixture:one" in agent_names) == (mode == "partial")
    issues = [issue for issue in report["scan_run"].get("issues", []) if issue.get("source") == provider]
    if mode == "empty":
        assert issues == []
    else:
        assert issues and all("Assessment incomplete" in issue["message"] or "did not complete" in issue["message"] for issue in issues)
