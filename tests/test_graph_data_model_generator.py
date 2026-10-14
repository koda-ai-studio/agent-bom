"""The generated graph data-model reference stays current and complete."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from agent_bom.core.entity_types import EntityType
from agent_bom.graph.edge_evidence import EDGE_EVIDENCE_TIERS
from agent_bom.graph.relationship_specs import TraversalClass
from agent_bom.graph.types import RelationshipType

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "generate_graph_data_model.py"


def _load_generator():
    name = "generate_graph_data_model"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _all_docs_text() -> str:
    gen = _load_generator()
    return "\n".join(gen.render().values())


def test_check_mode_passes_on_committed_docs() -> None:
    gen = _load_generator()
    assert gen.main(["--check"]) == 0


def test_check_mode_fails_when_a_committed_doc_drifts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gen = _load_generator()
    rendered = gen.render()
    for rel_path, text in rendered.items():
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    monkeypatch.setattr(gen, "ROOT", tmp_path)
    assert gen.main(["--check"]) == 0
    first = next(iter(rendered))
    (tmp_path / first).write_text(rendered[first] + "\nhand edit\n", encoding="utf-8")
    assert gen.main(["--check"]) == 1


def test_render_is_deterministic() -> None:
    gen = _load_generator()
    assert gen.render() == gen.render()


def test_every_relationship_entity_and_tier_is_documented() -> None:
    text = _all_docs_text()
    for rel in RelationshipType:
        assert f"`{rel.value}`" in text, rel
    for entity in EntityType:
        assert f"`{entity.value}`" in text, entity
    for tier in EDGE_EVIDENCE_TIERS:
        assert f"`{tier}`" in text, tier
    for traversal in TraversalClass:
        assert f"`{traversal.value}`" in text, traversal


def test_relationship_rows_carry_their_spec_traversal_class() -> None:
    from agent_bom.graph.relationship_specs import RELATIONSHIP_SPECS

    text = _all_docs_text()
    for rel, spec in RELATIONSHIP_SPECS.items():
        row = next(line for line in text.splitlines() if line.startswith(f"| `{rel.value}` |"))
        assert f"`{spec.traversal_class.value}`" in row, row


def test_mermaid_diagram_present_and_names_every_relationship() -> None:
    gen = _load_generator()
    main_doc = gen.render()[gen.MAIN_DOC]
    assert "```mermaid" in main_doc
    block = main_doc.split("```mermaid", 1)[1].split("```", 1)[0]
    for rel in RelationshipType:
        assert rel.value in block, rel


def test_every_generated_file_respects_the_line_ceiling() -> None:
    gen = _load_generator()
    for rel_path, text in gen.render().items():
        assert len(text.splitlines()) <= 1000, rel_path


def test_trace_event_section_follows_the_runtime_type(monkeypatch: pytest.MonkeyPatch) -> None:
    gen = _load_generator()
    from dataclasses import dataclass

    @dataclass
    class NormalizedTraceEvent:
        """A vendor trace event in one shape."""

        trace_id: str
        vendor: str

    fake = types.ModuleType("agent_bom.runtime.fake_trace")
    fake.NormalizedTraceEvent = NormalizedTraceEvent  # type: ignore[attr-defined]
    monkeypatch.setattr(gen, "_find_trace_event_type", lambda: NormalizedTraceEvent)
    text = "\n".join(gen.render().values())
    assert "Normalized trace event" in text
    assert "`trace_id`" in text and "`vendor`" in text

    monkeypatch.setattr(gen, "_find_trace_event_type", lambda: None)
    text = "\n".join(gen.render().values())
    assert "Normalized trace event" not in text
