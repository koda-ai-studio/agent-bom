"""Every registered MCP estate read answers a seed in progress with the typed retryable refusal, never an internal error."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest

from agent_bom.demo_estate import boot_seed
from agent_bom.mcp_tools.tool_capabilities import _TOOL_CAPABILITY_CLASSES
from tests.test_current_estate_seeding_refusal import NODE, TENANT, client  # noqa: F401 - pytest fixture

_ESTATE_CAPABILITIES = {"GRAPH", "INVENTORY", "COMPLIANCE"}
_HOST_CAPABILITIES = {"WRITE", "NETWORK", "LOCAL_FILE_READ", "THREAT_INTEL"}
_ESTATE_TOOLS_WITHOUT_ESTATE_CAPABILITY = {"blast_radius", "findings_query"}
# Benchmarks this host's own agent configuration; it never reads the tenant estate.
_HOST_BENCHMARKS = {"aisvs_benchmark"}
# Reads that name a recorded snapshot or a correlation record, not the current estate.
_PINNED_BY_CONTRACT = {"compromise_assessment", "consequence_assessment", "graph_correlation_status"}

ARGUMENTS: dict[str, dict] = {
    "blast_radius": {"cve_id": "CVE-2024-3094"},
    "inventory_asset": {"asset_id": NODE},
    "should_i_deploy": {"candidate": NODE},
    "graph_reach": {"node_id": NODE},
    "finding_detail": {"finding_id": "finding-1"},
    "graph_correlation_status": {"correlation_id": "corr-1"},
    "compromise_assessment": {"root_node_id": NODE, "scan_id": "shared-scan", "assume_control": True},
    "consequence_assessment": {
        "scan_id": "shared-scan",
        "request": {"root_node_id": NODE, "mode": "assumed_compromise", "assume_control": True},
    },
}


def _estate_tool(name: str) -> bool:
    capabilities = set(_TOOL_CAPABILITY_CLASSES.get(name, []))
    if capabilities & _HOST_CAPABILITIES or name in _HOST_BENCHMARKS:
        return False
    return bool(capabilities & _ESTATE_CAPABILITIES) or name in _ESTATE_TOOLS_WITHOUT_ESTATE_CAPABILITY


@pytest.fixture
def mcp(client, monkeypatch):  # noqa: F811 - the imported fixture
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    from agent_bom.mcp_server import create_mcp_server

    return create_mcp_server(profile="full")


@pytest.fixture
def live_seed_marker():
    assert boot_seed._boot_seed_done.is_set()
    boot_seed.mark_seed_started((TENANT,))
    yield
    boot_seed.clear_seed_marker()


def _estate_tool_names() -> list[str]:
    from agent_bom.mcp_server import create_mcp_server

    tools = asyncio.run(create_mcp_server(profile="full").list_tools())
    return sorted(tool.name for tool in tools if _estate_tool(tool.name))


ESTATE_TOOLS = _estate_tool_names()


def test_the_enumeration_covers_the_known_estate_reads():
    expected = {"inventory_list", "exposure_paths", "graph_diff", "findings_query", "finding_detail", "compliance", "blast_radius"}
    assert expected <= set(ESTATE_TOOLS), ESTATE_TOOLS


@pytest.mark.parametrize("name", ESTATE_TOOLS)
def test_estate_tool_never_answers_a_seed_with_an_internal_error(mcp, live_seed_marker, caplog, name):
    with caplog.at_level(logging.WARNING):
        result = asyncio.run(mcp.call_tool(name, ARGUMENTS.get(name, {})))
    payload = json.loads(result.content[0].text)
    error = payload.get("error") if isinstance(payload, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    assert code != "AGENTBOM_MCP_INTERNAL_UNEXPECTED", payload
    assert "Traceback" not in caplog.text, caplog.text
    if name not in _PINNED_BY_CONTRACT:
        assert code == "AGENTBOM_MCP_UPSTREAM_UNAVAILABLE", payload
        assert error["details"] == {"reason": "current_estate_seeding", "retry_after_seconds": 2}, payload


def test_blast_radius_maps_a_refusal_raised_mid_read_to_the_typed_error(caplog):
    from agent_bom.api import current_graph
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    def rotating(**_kwargs):
        raise current_graph._generation_rotating()

    async def no_scan(*_args, **_kwargs):
        raise AssertionError("must not scan")

    with caplog.at_level(logging.WARNING):
        raw = asyncio.run(
            blast_radius_impl(
                cve_id="CVE-2024-3094",
                _validate_cve_id=lambda value: value,
                _run_scan_pipeline=no_scan,
                _truncate_response=lambda value: value,
                _get_persisted_evidence=rotating,
            )
        )
    error = json.loads(raw)["error"]
    assert error["code"] == "AGENTBOM_MCP_UPSTREAM_UNAVAILABLE", error
    assert error["details"] == {"reason": current_graph.ROTATING_CODE, "retry_after_seconds": 1}
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR], caplog.text
