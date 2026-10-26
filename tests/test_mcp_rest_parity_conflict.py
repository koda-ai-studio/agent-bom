"""A REST 409 reaches MCP callers as a typed conflict, not as a malformed argument."""

from __future__ import annotations

import json

import pytest
from fastapi import HTTPException

from agent_bom.mcp_tools.rest_parity import _error_for_status


@pytest.mark.parametrize(
    ("status", "code", "category"),
    [
        (409, "AGENTBOM_MCP_CONFLICT_STATE", "conflict"),
        (404, "AGENTBOM_MCP_NOT_FOUND_RESOURCE", "not_found"),
        (422, "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT", "validation"),
    ],
)
def test_status_maps_to_a_typed_error(status, code, category):
    error = json.loads(_error_for_status(HTTPException(status_code=status, detail="A compared snapshot changed; restart.")))["error"]

    assert (error["code"], error["category"]) == (code, category)
    assert error["message"] == "A compared snapshot changed; restart."
