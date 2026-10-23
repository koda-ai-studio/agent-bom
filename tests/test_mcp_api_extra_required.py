"""Tools backed by API routes must say they need agent-bom[api] on a base install."""

from __future__ import annotations

import builtins
import json
import sys

import pytest


@pytest.mark.asyncio
async def test_audit_integrity_without_fastapi_names_the_api_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_tools.runtime import audit_integrity_impl

    real_import = builtins.__import__

    def _no_fastapi(name, *args, **kwargs):
        if name == "fastapi" or name.startswith("fastapi."):
            raise ModuleNotFoundError("No module named 'fastapi'", name="fastapi")
        return real_import(name, *args, **kwargs)

    for module in [m for m in sys.modules if m == "agent_bom.api.routes.enterprise" or m.startswith("fastapi")]:
        monkeypatch.delitem(sys.modules, module)
    monkeypatch.setattr(builtins, "__import__", _no_fastapi)
    payload = json.loads(await audit_integrity_impl(_truncate_response=lambda s: s))
    error = payload["error"]
    assert error["code"] == "AGENTBOM_MCP_UNSUPPORTED_BACKEND"
    assert "agent-bom[api]" in error["message"]
    assert error["details"] == {"missing_module": "fastapi", "install": "pip install 'agent-bom[api]'"}
