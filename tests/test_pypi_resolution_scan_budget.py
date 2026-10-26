"""All unlocked manifests in one scan share a single registry-resolution deadline."""

from __future__ import annotations

import time

from agent_bom.parsers import pypi_resolution
from agent_bom.scanners.state import reset_scan_warnings


def test_the_deadline_is_shared_across_manifests_and_reset_per_scan(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_PYPI_RESOLUTION_BUDGET_SECONDS", "5")
    reset_scan_warnings()
    first = pypi_resolution.scan_resolution_deadline()
    time.sleep(0.01)
    assert pypi_resolution.scan_resolution_deadline() == first
    assert first - time.monotonic() <= 5
    reset_scan_warnings()
    assert pypi_resolution.scan_resolution_deadline() > first


def test_default_shared_budget_fits_inside_an_mcp_tool_call(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_PYPI_RESOLUTION_BUDGET_SECONDS", raising=False)
    reset_scan_warnings()
    assert pypi_resolution.scan_resolution_deadline() - time.monotonic() <= 15
