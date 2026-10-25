"""MCP ``affected_assets`` returns exactly the REST affected-assets answer."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api import compliance_hub_store
from agent_bom.api.operator_advisory_store import InMemoryOperatorAdvisoryStore
from agent_bom.api.server import app
from agent_bom.api.storage.hub_memory import InMemoryComplianceHubStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store, set_operator_advisory_store
from agent_bom.db import schema
from agent_bom.mcp_errors import CODE_NOT_FOUND_RESOURCE, CODE_UPSTREAM_UNAVAILABLE, CODE_VALIDATION_INVALID_ARGUMENT
from tests.api.test_advisory_affected_api import ADVISORY, REPORTS, ROUTE, _job

TENANT = "default"


@pytest.fixture()
def control_plane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    monkeypatch.setattr(schema, "DB_PATH", tmp_path / "absent" / "vulns.db")
    jobs = InMemoryJobStore()
    for report in REPORTS:
        jobs.put(_job(TENANT, report))
    jobs.put(_job("tenant-other", REPORTS[0]))
    set_job_store(jobs)
    store = InMemoryOperatorAdvisoryStore()
    store.put(TENANT, ADVISORY)
    set_operator_advisory_store(store)
    compliance_hub_store.set_compliance_hub_store(InMemoryComplianceHubStore())
    yield TestClient(app)
    set_operator_advisory_store(None)
    compliance_hub_store.reset_compliance_hub_store()


def _mcp(**kwargs) -> dict:
    from agent_bom.mcp_tools.affected_assets import affected_assets_impl

    return json.loads(asyncio.run(affected_assets_impl(**kwargs)))


def test_mcp_matches_rest_page_for_page(control_plane: TestClient) -> None:
    rest = control_plane.get(ROUTE.format("CVE-2026-109618"), params={"limit": 2}).json()
    mcp = _mcp(advisory_id="CVE-2026-109618", limit=2)
    assert mcp == rest
    assert [row["verdict"] for row in mcp["rows"]] == ["affected", "possibly_affected"]
    rest_next = control_plane.get(ROUTE.format("CVE-2026-109618"), params={"limit": 2, "cursor": rest["next_cursor"]}).json()
    assert _mcp(advisory_id="CVE-2026-109618", limit=2, cursor=mcp["next_cursor"]) == rest_next


def test_mcp_unknown_advisory_is_not_found(control_plane: TestClient) -> None:
    assert _mcp(advisory_id="CVE-2026-0000001")["error"]["code"] == CODE_NOT_FOUND_RESOURCE


def test_mcp_rejects_bad_arguments(control_plane: TestClient) -> None:
    assert _mcp(advisory_id="CVE-2026-109618", verdict="safe")["error"]["code"] == CODE_VALIDATION_INVALID_ARGUMENT
    assert _mcp(advisory_id="CVE-2026-109618", limit=0)["error"]["code"] == CODE_VALIDATION_INVALID_ARGUMENT
    assert _mcp(advisory_id="", limit=5)["error"]["code"] == CODE_VALIDATION_INVALID_ARGUMENT
    assert _mcp(advisory_id="CVE-2026-109618", cursor="junk")["error"]["code"] == CODE_VALIDATION_INVALID_ARGUMENT


def test_mcp_refuses_typed_while_seeding(control_plane: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_bom.api.current_graph.demo_estate_seeding", lambda tenant_id=None: True)
    error = _mcp(advisory_id="CVE-2026-109618")["error"]
    assert error["code"] == CODE_UPSTREAM_UNAVAILABLE
    assert error["details"]["retry_after_seconds"] >= 1


def test_mcp_tenant_sees_only_its_own_estate(control_plane: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-other")
    assert _mcp(advisory_id="CVE-2026-109618")["error"]["code"] == CODE_NOT_FOUND_RESOURCE


def test_tool_is_registered_read_only_in_the_graph_profile() -> None:
    from agent_bom.mcp_tools.profiles import get_profile
    from agent_bom.mcp_tools.tool_capabilities import _TOOL_CAPABILITY_CLASSES

    assert "affected_assets" in (get_profile("graph").tools or set())
    assert _TOOL_CAPABILITY_CLASSES["affected_assets"][0] == "READ"
