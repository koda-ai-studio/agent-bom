"""Every name a module declares in ``__all__`` must resolve on that module.

Re-exports and cross-module constants are declared in ``__all__`` so static
analysis treats them as the module's export list. A stale entry (a name that
was renamed, moved or deleted) would break ``from module import *`` and mislead
readers, so this walks every ``src/agent_bom`` module with a literal
``__all__`` and checks each entry.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
PACKAGE = SRC / "agent_bom"


def _declared_all(path: Path) -> list[str] | None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
            value = node.value
            if isinstance(value, (ast.List, ast.Tuple)) and all(isinstance(e, ast.Constant) for e in value.elts):
                return [str(e.value) for e in value.elts]
    return None


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _modules_with_all() -> list[tuple[str, list[str]]]:
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        names = _declared_all(path)
        if names:
            found.append((_module_name(path), names))
    return found


MODULES = _modules_with_all()


def test_declared_exports_are_unique_per_module() -> None:
    duplicated = {module: sorted({n for n in names if names.count(n) > 1}) for module, names in MODULES if len(set(names)) != len(names)}
    assert duplicated == {}


@pytest.mark.parametrize(("module_name", "names"), MODULES, ids=[module for module, _ in MODULES])
def test_every_declared_export_resolves(module_name: str, names: list[str]) -> None:
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name and not exc.name.startswith("agent_bom"):
            pytest.skip(f"optional dependency {exc.name} not installed")
        raise
    missing = [name for name in names if not hasattr(module, name)]
    assert missing == [], f"{module_name}.__all__ lists names the module does not define: {missing}"


def test_quality_cleanup_preserves_existing_compatibility_reexports() -> None:
    """Import cleanup must retain the explicitly aliased compatibility bindings."""
    import json

    fixture = Path(__file__).parent / "fixtures" / "compatibility_reexports.json"
    expected = json.loads(fixture.read_text(encoding="utf-8"))
    missing = {}
    for module_name, names in expected.items():
        module = importlib.import_module(module_name)
        absent = [name for name in names if not hasattr(module, name)]
        if absent:
            missing[module_name] = absent
    assert missing == {}, f"Removed compatibility re-exports: {missing}"
