"""Graph responses encode with the stdlib JSON encoder, not a recursive walk.

Profiled on the demo estate's default ``GET /v1/graph`` (1,207 nodes, 1,994
edges): ``jsonable_encoder`` visited 242,434 objects and took more than half of
the warm request, only to hand plain dicts/lists/strings back to ``json.dumps``.
The bytes must stay the same as the old path for every value a payload can hold.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from enum import Enum

import pytest
from fastapi.encoders import jsonable_encoder

from agent_bom.api.routes.graph_routes import payloads
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode


class _Color(Enum):
    RED = "red"


def _payload() -> dict:
    node = UnifiedNode(id="pkg:a", entity_type=EntityType.PACKAGE, label="a", attributes={"tags": ("x", "y"), "n": 1.5})
    edge = UnifiedEdge(source="pkg:a", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO)
    return {
        "scan_id": "current-estate:abc",
        "nodes": [node.to_dict()],
        "edges": [edge.to_dict()],
        "odd": {
            "set": {3},
            "enum": _Color.RED,
            "str_enum": EntityType.AGENT,
            "when": datetime(2026, 10, 19, tzinfo=timezone.utc),
            "tuple": (1, 2),
        },
        "unicode": "café",
    }


def test_encoded_body_matches_the_recursive_encoder() -> None:
    payload = _payload()
    body = json.loads(payloads._encoded_graph_response(payload).body)
    assert body == jsonable_encoder({**payload, "evidence_scope": "current_estate"})


def test_plain_payload_never_takes_the_recursive_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(payloads, "jsonable_encoder", lambda value: calls.append(value) or value)
    plain = {"scan_id": "s", "nodes": [UnifiedNode(id="n", entity_type=EntityType.AGENT, label="n").to_dict()]}
    response = payloads._encoded_graph_response(plain)
    assert json.loads(response.body)["nodes"][0]["id"] == "n"
    assert calls == []
    assert response.media_type == "application/json"


def test_non_finite_numbers_still_fail_closed() -> None:
    with pytest.raises(ValueError):
        payloads._encoded_graph_response({"scan_id": "s", "risk": math.nan})
