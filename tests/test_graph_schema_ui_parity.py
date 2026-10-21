from __future__ import annotations

import re
from pathlib import Path

from agent_bom.graph import FINDING_ENTITY_TYPES, EntityType, GraphLayout, GraphSemanticLayer, RelationshipType
from agent_bom.graph.severity import SEVERITY_RANK

ROOT = Path(__file__).resolve().parent.parent
TS_GRAPH_SCHEMA = ROOT / "ui" / "lib" / "graph-schema.ts"
TS_SOURCE = TS_GRAPH_SCHEMA.read_text(encoding="utf-8")
TS_GENERATED_GRAPH_SCHEMA = ROOT / "ui" / "lib" / "graph-schema.generated.ts"
TS_GENERATED_SOURCE = TS_GENERATED_GRAPH_SCHEMA.read_text(encoding="utf-8")


def _block_after(marker: str, opener: str, closer: str, *, source: str = TS_SOURCE) -> str:
    start = source.index(marker)
    open_idx = source.index(opener, start)
    depth = 0
    for idx in range(open_idx, len(source)):
        char = source[idx]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return source[open_idx + 1 : idx]
    raise AssertionError(f"Could not parse block for {marker}")


def _ts_enum_values(name: str, *, source: str = TS_SOURCE) -> set[str]:
    body = _block_after(f"export enum {name}", "{", "}", source=source)
    return {value for _key, value in re.findall(r"(\w+)\s*=\s*\"([^\"]+)\"", body)}


def _ts_const_string_list(name: str, *, source: str = TS_SOURCE) -> list[str]:
    start = source.index(f"export const {name}")
    assignment = source.index("=", start)
    body = _block_after("=", "[", "]", source=source[assignment:])
    return re.findall(r"\"([^\"]+)\"", body)


def _ts_object_mapping(name: str) -> dict[str, int | float]:
    body = _block_after(f"export const {name}", "{", "}")
    mapping: dict[str, int | float] = {}
    for raw_key, raw_value in re.findall(r"^\s*([A-Za-z_]+):\s*([^,\n]+)", body, re.MULTILINE):
        value = raw_value.strip()
        if re.fullmatch(r"\d+", value):
            mapping[raw_key] = int(value)
        elif re.fullmatch(r"\d+\.\d+", value):
            mapping[raw_key] = float(value)
    return mapping


def test_ui_entity_types_match_python_graph_schema():
    assert _ts_enum_values("EntityType") == {entity.value for entity in EntityType}


def test_ui_relationship_types_match_python_graph_schema():
    assert _ts_enum_values("RelationshipType") == {relationship.value for relationship in RelationshipType}


def test_ui_graph_layouts_match_python_graph_schema():
    assert _ts_enum_values("GraphLayout") == {layout.value for layout in GraphLayout}


def test_generated_schema_semantic_layers_match_python_graph_schema():
    expected = [layer.value for layer in GraphSemanticLayer]
    assert _ts_enum_values("GraphSemanticLayer", source=TS_GENERATED_SOURCE) == set(expected)
    assert _ts_const_string_list("GRAPH_SEMANTIC_LAYERS", source=TS_GENERATED_SOURCE) == expected


def test_ui_severity_rank_matches_python_graph_schema():
    assert _ts_object_mapping("SEVERITY_RANK") == SEVERITY_RANK


def test_ui_finding_entity_types_match_python_graph_schema():
    body = _block_after("export const FINDING_ENTITY_TYPES", "[", "]")
    ts_findings = {match.split(".", 1)[1].strip() for match in re.findall(r"EntityType\.\w+", body)}
    assert ts_findings == {entity.name for entity in FINDING_ENTITY_TYPES}
