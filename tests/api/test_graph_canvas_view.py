"""``GET /v1/graph?view=canvas``: the graph page's projection without fields it never reads.

The default projection is the public contract for API and MCP clients and is
unchanged. The canvas view drops only fields that no module the graph page
loads reads before a selection (a selection refetches ``/v1/graph/node/{id}``
and merges the full node back), plus edge aliases of ``source``/``target``.
"""

from __future__ import annotations

import copy
import pathlib
import re

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.routes.graph_routes.canvas_view import (
    CANVAS_DROPPED_EDGE_FIELDS,
    CANVAS_DROPPED_NODE_ATTRIBUTES,
    CANVAS_DROPPED_NODE_FIELDS,
)
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests.test_graph_api import _RecordingGraphStore

UI = pathlib.Path(__file__).resolve().parents[2] / "ui"
GRAPH_PAGE_ENTRY = UI / "app" / "graph" / "page.tsx"
# Reads in the graph page's modules that are not reads of the canvas payload.
NOT_CANVAS_READS = {
    # Reads the selection refetch (detail.node), not the canvas node.
    ("evidence_provenance", "lib/graph-entity-detail.ts"),
    # Reads /v1/graph/edges/changes rows, a different response.
    ("source_id", "components/graph-edge-changes-panel.tsx"),
    ("target_id", "components/graph-edge-changes-panel.tsx"),
}


@pytest.fixture
def recording_graph_store():
    original = api_stores._graph_store
    store = _RecordingGraphStore()
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
    heavy = {key: f"value-{key}" for key in CANVAS_DROPPED_NODE_ATTRIBUTES}
    heavy["finding_ids_by_asset"] = {"pkg:a": ["f-1"]}
    graph.add_node(
        UnifiedNode(
            id="agent:a",
            entity_type=EntityType.AGENT,
            label="agent-a",
            attributes={**heavy, "cloud_provider": "aws", "account_scope": "111"},
        )
    )
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s", attributes={"owner": "team"}))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, evidence={"source": "scan"}))
    return graph


def _strip(payload: dict) -> dict:
    expected = copy.deepcopy(payload)
    for node in expected["nodes"]:
        for field in CANVAS_DROPPED_NODE_FIELDS:
            node.pop(field, None)
        for key in CANVAS_DROPPED_NODE_ATTRIBUTES:
            (node.get("attributes") or {}).pop(key, None)
    for edge in expected["edges"]:
        for field in CANVAS_DROPPED_EDGE_FIELDS:
            edge.pop(field, None)
    expected["view"] = "canvas"
    return expected


@pytest.mark.parametrize("extra", [{"limit": 5}, {"relationships": "uses"}], ids=["node-page", "investigation-load"])
def test_canvas_view_is_the_default_minus_only_the_unread_fields(recording_graph_store, extra, monkeypatch) -> None:
    # Investigation loads merge process-global runtime evidence; another test's records must not leak in.
    from agent_bom.cloud import runtime_workload_evidence_store as runtime_evidence

    monkeypatch.setattr(runtime_evidence, "_default_store", None)
    recording_graph_store.graph = _graph()
    client = TestClient(app)
    params = {"scan": "store-scan", **extra}

    full = client.get("/v1/graph", params=params)
    canvas = client.get("/v1/graph", params={**params, "view": "canvas"})

    assert full.status_code == canvas.status_code == 200, canvas.text
    full_body, canvas_body = full.json(), canvas.json()
    assert "view" not in full_body
    assert canvas_body == _strip(full_body)
    # The default projection still carries every field the canvas drops.
    node = next(n for n in full_body["nodes"] if n["id"] == "agent:a")
    assert set(CANVAS_DROPPED_NODE_ATTRIBUTES) <= set(node["attributes"])
    assert {"source_id", "target_id"} <= set(full_body["edges"][0])
    assert len(canvas.content) < len(full.content)


def test_unknown_view_is_rejected(recording_graph_store) -> None:
    recording_graph_store.graph = _graph()
    assert TestClient(app).get("/v1/graph", params={"scan": "store-scan", "view": "slim"}).status_code == 422


_IMPORT = re.compile(r"""(?:from|import)\s*\(?\s*["'](@/|\./|\.\./)([^"']+)["']""")


def _resolve(base: pathlib.Path, prefix: str, spec: str) -> pathlib.Path | None:
    target = ((UI / spec) if prefix == "@/" else (base.parent / (prefix + spec))).resolve()
    for candidate in (target, target.with_name(target.name + ".ts"), target.with_name(target.name + ".tsx"), target / "index.ts"):
        if candidate.is_file():
            return candidate
    return None


def _graph_page_modules() -> list[pathlib.Path]:
    seen: set[pathlib.Path] = set()
    todo = [GRAPH_PAGE_ENTRY]
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        for prefix, spec in _IMPORT.findall(current.read_text(encoding="utf-8")):
            resolved = _resolve(current, prefix, spec)
            if resolved is not None and "generated" not in resolved.name:
                todo.append(resolved)
    return sorted(path for path in seen if not re.search(r"\.(test|spec)\.", path.name))


def _runtime_field_pattern_matches(line: str, pattern: re.Pattern[str], *, relative: str) -> bool:
    if relative == "lib/graph-schema.ts":
        # GraphApiSchemas is a type alias of the generated API components. Indexed
        # type lookups emit no JavaScript; keep checking actual reads on the line.
        line = re.sub(r'(:\s*)GraphApiSchemas(?:\["[A-Za-z_][A-Za-z_0-9]*"\])+', r"\1", line)
    return pattern.search(line) is not None


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('activity_id?: GraphApiSchemas["GraphEdgeRecord"]["activity_id"];', False),
        ("const value = edge.activity_id;", True),
        ('const value = GraphApiSchemas["GraphEdgeRecord"]["activity_id"];', True),
        ("const value = edge?.activity_id;", True),
        ('const value = edge["activity_id"];', True),
        ('const key = "activity_id";', True),
        ('const value: GraphApiSchemas["GraphEdgeRecord"]["activity_id"] = edge.activity_id;', True),
    ],
)
def test_canvas_guard_distinguishes_type_lookups_from_runtime_reads(line, expected):
    pattern = re.compile(r"(?:\?\.|\.)activity_id\b|[\"'`]activity_id[\"'`]")
    assert _runtime_field_pattern_matches(line, pattern, relative="lib/graph-schema.ts") is expected


def test_no_graph_page_module_reads_a_field_the_canvas_view_drops() -> None:
    modules = _graph_page_modules()
    assert len(modules) > 50, "graph page import closure did not resolve"
    dropped = {*CANVAS_DROPPED_NODE_FIELDS, *CANVAS_DROPPED_NODE_ATTRIBUTES, *CANVAS_DROPPED_EDGE_FIELDS}
    reads = []
    for key in sorted(dropped):
        pattern = re.compile(r"(?:\?\.|\.)" + re.escape(key) + r"\b|[\"'`]" + re.escape(key) + r"[\"'`]")
        for module in modules:
            relative = module.relative_to(UI).as_posix()
            if (key, relative) in NOT_CANVAS_READS:
                continue
            for number, line in enumerate(module.read_text(encoding="utf-8").splitlines(), 1):
                if _runtime_field_pattern_matches(line, pattern, relative=relative):
                    reads.append(f"{relative}:{number} reads {key}")
    assert reads == []


def test_the_graph_page_requests_the_canvas_view() -> None:
    hook = (UI / "hooks" / "use-graph-page-data.tsx").read_text(encoding="utf-8")
    assert 'view: "canvas"' in hook
