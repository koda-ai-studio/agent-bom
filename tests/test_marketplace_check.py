"""Tests for marketplace_check MCP tool trust signals."""

import pytest

from agent_bom.mcp_server import create_mcp_server
from agent_bom.mcp_tools.registry import marketplace_trust_signals


@pytest.fixture
def mcp():
    return create_mcp_server(profile="full")


def test_marketplace_tool_registered(mcp):
    """marketplace_check should be registered as a tool."""
    import asyncio

    assert "marketplace_check" in {tool.name for tool in asyncio.run(mcp.list_tools())}


def test_trust_signals_no_cves():
    """A clean, widely adopted package gets no-known-cves and high-adoption."""
    signals = marketplace_trust_signals(cve_count=0, registry_verified=False, download_count=200_000, license_info=None)

    assert signals == ["no-known-cves", "high-adoption"]


def test_trust_signals_with_cves():
    """Trust signals should NOT include 'no-known-cves' when vulnerable."""
    signals = marketplace_trust_signals(cve_count=3, registry_verified=False, download_count=0, license_info=None)

    assert signals == []


def test_trust_signals_registry_verified():
    """A registry-listed package below the adoption floor gets only registry-verified."""
    signals = marketplace_trust_signals(cve_count=1, registry_verified=True, download_count=5_000, license_info=None)

    assert signals == ["registry-verified"]


@pytest.mark.parametrize(
    ("downloads", "expected"),
    [(10_000, []), (10_001, ["moderate-adoption"]), (100_000, ["moderate-adoption"]), (100_001, ["high-adoption"])],
)
def test_trust_signals_adoption_thresholds(downloads, expected):
    signals = marketplace_trust_signals(cve_count=1, registry_verified=False, download_count=downloads, license_info=None)

    assert signals == expected


def test_trust_signals_license_is_last():
    signals = marketplace_trust_signals(cve_count=0, registry_verified=True, download_count=50_000, license_info="MIT")

    assert signals == ["no-known-cves", "registry-verified", "moderate-adoption", "license:MIT"]
