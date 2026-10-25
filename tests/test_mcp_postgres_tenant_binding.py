"""Every MCP tool call reads Postgres under the server-bound tenant, not ``default``."""

from __future__ import annotations

import asyncio

import pytest

from agent_bom import mcp_server
from agent_bom.api import postgres_common


@pytest.fixture
def postgres_bound_to_tenant_a(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@127.0.0.1:1/unused")
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")


def test_sync_tool_reads_under_the_bound_tenant_and_resets(postgres_bound_to_tenant_a):
    seen: list[str] = []

    def handler() -> str:
        seen.append(postgres_common._current_tenant.get())
        return "{}"

    asyncio.run(mcp_server._execute_tool_sync_async("probe", handler))
    assert seen == ["tenant-a"]
    assert postgres_common._current_tenant.get() == "default"


def test_async_tool_reads_under_the_bound_tenant_and_resets(postgres_bound_to_tenant_a):
    seen: list[str] = []

    async def handler() -> str:
        seen.append(postgres_common._current_tenant.get())
        return "{}"

    asyncio.run(mcp_server._execute_tool_async("probe", handler))
    assert seen == ["tenant-a"]
    assert postgres_common._current_tenant.get() == "default"


def test_each_call_takes_the_tenant_bound_at_call_time(postgres_bound_to_tenant_a, monkeypatch):
    seen: list[str] = []

    def handler() -> str:
        seen.append(postgres_common._current_tenant.get())
        return "{}"

    asyncio.run(mcp_server._execute_tool_sync_async("probe", handler))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-b")
    asyncio.run(mcp_server._execute_tool_sync_async("probe", handler))
    assert seen == ["tenant-a", "tenant-b"]


def test_no_postgres_leaves_the_context_untouched(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    seen: list[str] = []

    def handler() -> str:
        seen.append(postgres_common._current_tenant.get())
        return "{}"

    asyncio.run(mcp_server._execute_tool_sync_async("probe", handler))
    assert seen == ["default"]
