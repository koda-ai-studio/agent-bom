"""Guards for the per-test and per-module seeded demo clients."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests import _demo_estate_fixtures as fixtures

_TESTS = Path(__file__).resolve().parent
_WRITES = {"post", "put", "patch", "delete", "save_graph", "maybe_bootstrap_demo_estate", "refresh_demo_daily_evidence"}


def _test_functions(path: Path) -> list[ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]


def _arguments(node: ast.FunctionDef) -> set[str]:
    return {arg.arg for arg in node.args.args}


def _shared_modules() -> list[Path]:
    return sorted(
        path for path in _TESTS.rglob("test_*.py") if any("shared_demo_estate_client" in _arguments(node) for node in _test_functions(path))
    )


def test_a_second_seed_in_one_process_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(fixtures, "_active_seeds", [tmp_path / "live"])

    with pytest.raises(RuntimeError, match="one demo client kind per module"):
        with fixtures.seeded_demo_estate(monkeypatch, tmp_path):
            pass


def test_shared_seed_modules_exist() -> None:
    assert _shared_modules(), "no module uses shared_demo_estate_client"


@pytest.mark.parametrize("path", _shared_modules(), ids=lambda path: path.name)
def test_shared_seed_modules_only_read(path: Path) -> None:
    """A module on the shared seed never mixes in per-test seeds, patches, or writes."""
    problems: list[str] = []
    for node in _test_functions(path):
        arguments = _arguments(node)
        if "demo_estate_client" in arguments:
            problems.append(f"{node.name} mixes the per-test seed into a shared-seed module")
        if "shared_demo_estate_client" not in arguments:
            continue
        if "monkeypatch" in arguments:
            problems.append(f"{node.name} patches process state under a shared seed")
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
                if name in _WRITES or name.startswith("seed_"):
                    problems.append(f"{node.name} calls {name}() under a shared seed")
    assert not problems, "\n".join(problems)
