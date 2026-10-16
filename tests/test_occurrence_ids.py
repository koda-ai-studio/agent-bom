"""Imported component identity is a declaration, never execution authority."""

import pytest

from agent_bom.evidence.occurrence_ids import server_occurrence_id
from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface

DECLARED = "575e032b-5e58-539e-85c6-cd9eba4abff2"


def _owner(scope):
    return Agent(name="reader", agent_type=AgentType.CUSTOM, config_path=f"/workspace/{scope}/mcp.json")


def test_declared_sbom_occurrence_does_not_change_with_import_location():
    server = MCPServer(name="imported", command="sbom", surface=ServerSurface.SBOM, imported_canonical_id=DECLARED)
    assert server_occurrence_id(server, _owner("one")) == server_occurrence_id(server, _owner("two")) == DECLARED


@pytest.mark.parametrize(
    "fields",
    [
        {"command": "execute", "surface": ServerSurface.SBOM, "imported_canonical_id": DECLARED},
        {"command": "python", "imported_canonical_id": DECLARED},
        {"command": "sbom", "surface": ServerSurface.SBOM, "imported_canonical_id": "not-a-uuid"},
        {"command": "sbom", "surface": ServerSurface.SBOM, "imported_canonical_id": "00000000-0000-4000-8000-000000000001"},
    ],
)
def test_live_or_invalid_declarations_cannot_override_scope(fields):
    server = MCPServer(name="reader", **fields)
    left = server_occurrence_id(server, _owner("one"))
    right = server_occurrence_id(server, _owner("two"))
    assert left != right
    assert DECLARED not in (left, right)
