"""The product-proof roll-up fixture is the backend roll-up of the demo graph, not hand-written numbers."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node reads the demo graph module")


def _generator():
    spec = importlib.util.spec_from_file_location("generate_product_proof_rollup", ROOT / "scripts" / "generate_product_proof_rollup.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_committed_fixture_matches_the_backend_rollup() -> None:
    assert _generator().main(["--check"]) == 0


def test_every_node_has_an_aggregate_and_every_entry_a_layer() -> None:
    generator = _generator()
    data = generator.demo_graph()
    fixture = generator.build_fixture(data)
    assert set(fixture["node_aggregates"]) == {node["id"] for node in data["nodes"]}
    assert all(entry["semantic_layer"] for entry in fixture["rollup"]["top_level"])
