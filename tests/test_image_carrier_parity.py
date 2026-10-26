"""The CLI, API and MCP scan surfaces build the same image carrier for the same image."""

from __future__ import annotations

import shutil
from types import SimpleNamespace
from typing import Any

import pytest
from rich.console import Console

from agent_bom.models import Agent
from agent_bom.oci_registry import client as registry_client
from tests._oci_image_builder import build_image, dpkg_status
from tests._oci_registry_fake import REGISTRY, FakeRegistry

REF = f"{REGISTRY}/team/api:2.0"


@pytest.fixture
def registry(monkeypatch):
    fake = FakeRegistry()
    monkeypatch.setattr(registry_client, "_default_transport", fake.transport)
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    image = build_image([{"var/lib/dpkg/status": dpkg_status(("bash", "5.2"))}])
    fake.push_image("team/api", image, "2.0")
    fake.image = image  # type: ignore[attr-defined]
    return fake


def _cli_carrier() -> Agent:
    from agent_bom.cli.agents._discovery_sources import scan_container_images

    run = SimpleNamespace(
        skill_only=False,
        images=(REF,),
        con=Console(quiet=True),
        extra={},
        registry_user=None,
        registry_pass=None,
        image_platform=None,
        ctx=SimpleNamespace(agents=[], policy_passed=True),
    )
    scan_container_images(run)  # type: ignore[arg-type]
    [agent] = run.ctx.agents
    return agent


def _api_carrier() -> Agent:
    from agent_bom.api.scan_discovery_stages import _discover_images

    warnings: list[str] = []
    ctx = SimpleNamespace(
        req=SimpleNamespace(images=[REF]),
        pipeline=SimpleNamespace(update_step=lambda *_args: None),
        agents=[],
        record_coverage_warning=warnings.append,
    )
    _discover_images(ctx)  # type: ignore[arg-type]
    assert not warnings
    [agent] = ctx.agents
    return agent


async def _mcp_carrier(monkeypatch) -> Agent:
    from agent_bom.mcp_server_scan import run_scan_pipeline

    async def scan(_agents, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", scan)
    agents, _, warnings, _ = await run_scan_pipeline(safe_path=lambda value: value, image=REF, no_discover=True)
    [agent] = agents
    assert not warnings
    return agent


def _identity(agent: Agent) -> dict[str, Any]:
    from agent_bom.graph.image_projection import carrier_node_id
    from agent_bom.models import AIBOMReport
    from agent_bom.output.json_fmt import to_json

    [serialized] = to_json(AIBOMReport(agents=[agent], blast_radii=[]))["agents"]
    return {
        "agent": (agent.name, agent.stable_id, agent.config_path, agent.source),
        "servers": [(s.name, s.stable_id, s.transport, s.surface, s.command, tuple(s.args)) for s in agent.mcp_servers],
        "role": {k: agent.metadata.get(k) for k in ("inventory_role", "image_ref", "image_digest")},
        "evidence": sorted(k for k in agent.metadata if k not in {"inventory_role", "image_ref", "image_digest"}),
        "image_node": carrier_node_id(serialized),
        "packages": sorted((p.name, p.version) for s in agent.mcp_servers for p in s.packages),
    }


@pytest.mark.asyncio
async def test_cli_api_and_mcp_build_identical_image_carriers(registry, monkeypatch):
    cli, api, mcp = _identity(_cli_carrier()), _identity(_api_carrier()), _identity(await _mcp_carrier(monkeypatch))

    assert cli["image_node"] == f"container:image:{REF}"
    assert cli["packages"] == [("bash", "5.2")]
    assert "image" in cli["evidence"]
    assert api == cli
    assert mcp == cli
