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


def test_overview_shows_the_diagram_and_domain_pages_name_every_relationship() -> None:
    gen = _load_generator()
    docs = gen.render()
    main_doc = docs[gen.MAIN_DOC]
    assert "graph-data-model-dark.svg" in main_doc and "graph-data-model-light.svg" in main_doc
    domain_pages = "".join(text for path, text in docs.items() if "/data-model/domains/" in path)
    for rel in RelationshipType:
        assert f"`{rel.value}`" in domain_pages, rel


def test_diagram_refuses_a_backbone_step_the_specs_do_not_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    gen = _load_generator()
    svg = gen.graph_data_model_svg
    monkeypatch.setattr(svg, "BACKBONE", ((("agent", "uses_credential", "credential"),),))
    with pytest.raises(SystemExit, match="does not allow|do not allow"):
        svg.render([], {}, {}, gen._specs())


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


def _write_store(root: Path, ddl: str) -> None:
    module = root / "src" / "agent_bom" / "fake_store.py"
    module.parent.mkdir(parents=True, exist_ok=True)
    module.write_text(f"import sqlite3\n\n_DDL = '''\n{ddl}\n'''\n", encoding="utf-8")


def test_storage_index_lists_every_table_from_the_ddl() -> None:
    gen = _load_generator()
    storage = gen.graph_data_model_storage
    tables = storage.extract_tables(gen.SOURCE_ROOT)
    assert len(tables) > 100
    assert {"graph_nodes", "graph_edges", "scan_jobs", "teams", "hub_findings_current"} <= set(tables)
    index = gen.render()[storage.INDEX_DOC]
    rows = {line.split("|")[1].strip().strip("`") for line in index.split("## Table index", 1)[1].splitlines() if line.startswith("| `")}
    assert set(tables) <= rows


def test_storage_domain_pages_each_carry_an_er_diagram() -> None:
    gen = _load_generator()
    storage = gen.graph_data_model_storage
    rendered = gen.render()
    tables = storage.assign_domains(storage.extract_tables(gen.SOURCE_ROOT))
    for key, _title, _exact, _prefixes in storage.DOMAINS:
        page = rendered[f"{storage.DOMAIN_DOC_DIR}/{key}.md"]
        block = page.split("```mermaid\nerDiagram\n", 1)[1].split("```", 1)[0]
        for table in (t for t in tables.values() if t.domain == key):
            assert f"  {table.name} {{" in block, (key, table.name)


def test_storage_relations_split_declared_and_logical(tmp_path: Path) -> None:
    gen = _load_generator()
    storage = gen.graph_data_model_storage
    _write_store(
        tmp_path,
        "CREATE TABLE IF NOT EXISTS scan_widgets (tenant_id TEXT NOT NULL, widget_id TEXT NOT NULL, PRIMARY KEY (tenant_id, widget_id));\n"
        "CREATE TABLE IF NOT EXISTS scan_widget_parts (tenant_id TEXT NOT NULL, part_id TEXT PRIMARY KEY, widget_id TEXT);\n"
        "CREATE TABLE IF NOT EXISTS scan_widget_notes (note_id TEXT PRIMARY KEY, part_id TEXT REFERENCES scan_widget_parts(part_id));\n"
        "CREATE TABLE IF NOT EXISTS graph_widget_copies (tenant_id TEXT NOT NULL, copy_id TEXT PRIMARY KEY, widget_id TEXT);",
    )
    tables = storage.assign_domains(storage.extract_tables(tmp_path))
    assert tables["scan_widget_notes"].foreign_keys == [("part_id", "scan_widget_parts", "part_id")]
    rels = {(r.parent, r.child, r.column, r.kind) for r in storage.relations(tables)}
    assert ("scan_widget_parts", "scan_widget_notes", "part_id", "fk") in rels
    assert ("scan_widgets", "scan_widget_parts", "widget_id", "logical") in rels
    # Logical joins stay inside one domain; tenant columns never become a join.
    assert not any(child == "graph_widget_copies" for _p, child, _c, _k in rels)
    assert not any(column in storage.TENANT_COLUMNS for _p, _c, column, _k in rels)


def test_unmapped_table_fails_generation(tmp_path: Path) -> None:
    gen = _load_generator()
    storage = gen.graph_data_model_storage
    _write_store(tmp_path, "CREATE TABLE IF NOT EXISTS brand_new_ledger (entry TEXT PRIMARY KEY)")
    with pytest.raises(SystemExit, match="brand_new_ledger"):
        storage.render(tmp_path, gen.GENERATOR)


def test_unresolvable_table_placeholder_fails_generation(tmp_path: Path) -> None:
    gen = _load_generator()
    storage = gen.graph_data_model_storage
    module = tmp_path / "src" / "agent_bom" / "dyn_store.py"
    module.parent.mkdir(parents=True)
    module.write_text('def ddl(name):\n    return f"CREATE TABLE IF NOT EXISTS {name} (id TEXT)"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="cannot resolve table name"):
        storage.extract_tables(tmp_path)


def test_check_mode_covers_the_storage_and_correlation_pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gen = _load_generator()
    rendered = gen.render()
    new_pages = [gen.graph_data_model_storage.INDEX_DOC, gen.graph_data_model_correlation.DOC]
    new_pages.append(f"{gen.graph_data_model_storage.DOMAIN_DOC_DIR}/graph.md")
    for rel_path, text in rendered.items():
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    monkeypatch.setattr(gen, "ROOT", tmp_path)
    for page in new_pages:
        assert page in rendered
        (tmp_path / page).write_text(rendered[page] + "\nhand edit\n", encoding="utf-8")
        assert gen.main(["--check"]) == 1
        (tmp_path / page).write_text(rendered[page], encoding="utf-8")
        assert gen.main(["--check"]) == 0
    main_doc = rendered[gen.MAIN_DOC]
    assert "(data-model/storage-erd.md)" in main_doc and "(data-model/correlation.md)" in main_doc


def test_correlation_page_follows_correlation_identity() -> None:
    gen = _load_generator()
    corr = gen.graph_data_model_correlation
    page = gen.render()[corr.DOC]
    assert "```mermaid\nflowchart LR" in page
    branches = corr.identity_branches()
    covered = [e for b in branches for e in b.entity_types]
    assert sorted(covered) == sorted(e.value for e in EntityType), "every entity type has exactly one merge branch"
    by_entity = corr.entity_branch(branches)
    assert "purl" in by_entity["package"].keys
    assert "arn" in by_entity["cloud_resource"].keys
    missing = page.split("## Not correlated across sources yet", 1)[1]
    listed = {line[3:-1] for line in missing.splitlines() if line.startswith("- `")}
    assert listed == set(corr.not_correlated(branches, gen.scan_source().node_id_formats))
    assert listed and all(by_entity[e].label == corr.FALLBACK_LABEL for e in listed)
    assert "package" not in listed and "cloud_resource" not in listed


def test_generator_path_does_not_import_the_api_framework() -> None:
    import subprocess

    code = (
        "import runpy, sys\n"
        f"sys.argv = ['g', '--check']\n"
        "try:\n"
        f"    runpy.run_path({str(SCRIPT_PATH)!r}, run_name='__main__')\n"
        "except SystemExit:\n"
        "    pass\n"
        "print('fastapi' in sys.modules)\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT)
    assert result.stdout.strip().splitlines()[-1] == "False"


def test_workspace_tables_are_labeled_scratch():
    gen = _load_generator()
    storage = gen.graph_data_model_storage
    tables = storage.extract_tables(gen.SOURCE_ROOT)
    scratch = [t for t in tables.values() if storage._storage_lifetime(t) == "scratch"]
    assert scratch
    assert all(t.dialects == ["sqlite"] or set(t.dialects) == {"sqlite"} for t in scratch)
    page = gen.render()[f"{storage.DOMAIN_DOC_DIR}/graph.md"]
    for table in scratch:
        assert any(line.startswith(f"| `{table.name}` |") and "scratch" in line for line in page.splitlines())


def test_technique_relationship_inventory_requires_source_backed_prerequisites() -> None:
    from agent_bom.graph.attack_path_mitre import MAPPED_RELATIONSHIPS

    assert MAPPED_RELATIONSHIPS == frozenset({RelationshipType.CAN_ACCESS, RelationshipType.INVOKED})
    text = _all_docs_text()
    assert "MAPPED_RELATIONSHIPS" in text
    assert "requires source-backed prerequisites" in text
    assert "_DATA_ACCESS_RELS" not in text
