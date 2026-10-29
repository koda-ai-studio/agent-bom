#!/usr/bin/env python3
"""Hard size ceiling: no file over 1,000 lines, no Python function over 150.

Covers ``src/agent_bom`` (files and functions, methods included) and the
hand-written dashboard sources under ``ui/app``, ``ui/components``, ``ui/lib``
and ``ui/hooks`` (files only). Generated TypeScript (``*.generated.ts``)
and vendored ``*.min.js`` bundles keep their owning
generation checks and are not measured.

Python allowances are not stored twice: ``scripts/check_architecture.py``
already ratchets every Python file (600 lines) and function (80 lines) in
``scripts/architecture-baseline.json``, so a Python unit over the ceiling is
allowed only up to the size recorded there, and that file's own ``--base-ref``
check stops the allowance from growing. Dashboard allowances live in
``scripts/line_ceiling_baseline.json``: an entry may shrink or disappear, never
grow or appear, and a stale entry (file back under the ceiling) must be removed
with ``--write-baseline``.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import subprocess
import sys
from pathlib import Path

try:
    from scripts.check_architecture import BASELINE as ARCHITECTURE_BASELINE
    from scripts.check_architecture import function_spans
except ModuleNotFoundError:  # run as ``python scripts/check_line_ceiling.py``
    from check_architecture import BASELINE as ARCHITECTURE_BASELINE
    from check_architecture import function_spans

ROOT = Path(__file__).resolve().parents[1]
FILE_CEILING = 1000
FUNCTION_CEILING = 150
PYTHON_ROOT = Path("src/agent_bom")
UI_ROOTS = (Path("ui/app"), Path("ui/components"), Path("ui/lib"), Path("ui/hooks"))
UI_SUFFIXES = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".css"})
GENERATED_UI_PATTERNS = ("*.generated.ts", "*.min.js")
BASELINE = Path("scripts/line_ceiling_baseline.json")


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def python_sizes(root: Path) -> dict[str, int]:
    """Line counts keyed like the architecture baseline: ``rel.py`` and ``rel.py::Qualified.name``."""
    source = root / PYTHON_ROOT
    sizes: dict[str, int] = {}
    for path in sorted(source.rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        text = path.read_text(encoding="utf-8")
        sizes[relative] = len(text.splitlines())
        for name, start, end in function_spans(ast.parse(text, filename=str(path))):
            sizes[f"{relative}::{name}"] = end - start + 1
    return sizes


def _is_generated(path: Path) -> bool:
    return any(fnmatch.fnmatch(path.name, pattern) for pattern in GENERATED_UI_PATTERNS)


def ui_sizes(root: Path) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for ui_root in UI_ROOTS:
        base = root / ui_root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in UI_SUFFIXES and not _is_generated(path) and "node_modules" not in path.parts:
                sizes[path.relative_to(root).as_posix()] = _line_count(path)
    return sizes


def python_allowances(root: Path) -> dict[str, int]:
    """Recorded Python debt from the architecture ratchet; the only Python exception source."""
    debt = json.loads((root / ARCHITECTURE_BASELINE).read_text(encoding="utf-8"))["debt"]
    allowances: dict[str, int] = {}
    for key, values in debt.items():
        metric = "function_lines" if "::" in key else "file_lines"
        if metric in values:
            allowances[key] = values[metric]
    return allowances


def load_ui_baseline(root: Path) -> dict[str, int]:
    path = root / BASELINE
    if not path.exists():
        return {}
    return dict(json.loads(path.read_text(encoding="utf-8"))["files"])


def current_ui_debt(root: Path) -> dict[str, int]:
    return {key: size for key, size in ui_sizes(root).items() if size > FILE_CEILING}


def _violations(sizes: dict[str, int], allowances: dict[str, int], prefix: str) -> list[str]:
    errors = []
    for key, size in sizes.items():
        is_function = "::" in key
        ceiling = FUNCTION_CEILING if is_function else FILE_CEILING
        allowance = allowances.get(key, 0)
        if size > ceiling and size > allowance:
            unit = "function" if is_function else "file"
            errors.append(f"{prefix}{key}: {size} lines exceeds the {ceiling}-line {unit} ceiling (allowance {allowance})")
    return errors


def baseline_growth(current: dict[str, int], base_counts: dict[str, int]) -> list[str]:
    """An edited dashboard baseline can only shrink or lose entries."""
    return [
        f"{key}: baseline allowance {value} exceeds trusted {base_counts.get(key, 0)}"
        for key, value in sorted(current.items())
        if value > base_counts.get(key, 0)
    ]


def check(
    root: Path,
    python_allowed: dict[str, int],
    ui_baseline: dict[str, int],
    *,
    base_ui_counts: dict[str, int] | None,
) -> list[str]:
    errors = _violations(python_sizes(root), python_allowed, f"{PYTHON_ROOT.as_posix()}/")
    sizes = ui_sizes(root)
    errors.extend(_violations(sizes, ui_baseline, ""))
    for key in sorted(ui_baseline):
        if sizes.get(key, 0) <= FILE_CEILING:
            errors.append(f"{key}: baseline entry is stale (file within the ceiling or removed); run --write-baseline")
        elif sizes[key] < ui_baseline[key]:
            errors.append(f"{key}: baseline allowance is stale ({ui_baseline[key]} recorded, {sizes[key]} current); run --write-baseline")
    if base_ui_counts is not None:
        errors.extend(baseline_growth(ui_baseline, base_ui_counts))
    return errors


def load_base_ref_counts(root: Path, ref: str) -> dict[str, int] | None:
    # A missing commit is an error; a missing file permits the initial rollout.
    subprocess.run(["git", "cat-file", "-e", f"{ref}^{{commit}}"], cwd=root, check=True, capture_output=True)
    exists = subprocess.run(["git", "cat-file", "-e", f"{ref}:{BASELINE.as_posix()}"], cwd=root, capture_output=True)
    if exists.returncode:
        return None
    content = subprocess.check_output(["git", "show", f"{ref}:{BASELINE.as_posix()}"], cwd=root, text=True)
    return dict(json.loads(content)["files"])


def summary(root: Path) -> str:
    python = python_sizes(root)
    files = sum(1 for key, size in python.items() if "::" not in key and size > FILE_CEILING)
    functions = sum(1 for key, size in python.items() if "::" in key and size > FUNCTION_CEILING)
    ui = len(current_ui_debt(root))
    above = f"{files} Python files, {functions} Python functions, {ui} dashboard files"
    return f"Line ceiling passed ({above} still above the ceiling, all recorded)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write-baseline", action="store_true", help="record the current dashboard debt; refuses growth")
    parser.add_argument("--base-ref", help="reference base commit used to reject increased baseline allowances")
    args = parser.parse_args()
    stored = load_ui_baseline(ROOT)
    base_counts = load_base_ref_counts(ROOT, args.base_ref) if args.base_ref else None
    if args.write_baseline:
        current = current_ui_debt(ROOT)
        errors = baseline_growth(current, stored) if (ROOT / BASELINE).exists() else []
        if base_counts is not None:
            errors.extend(baseline_growth(current, base_counts))
        if errors:
            print("\n".join(errors))
            return 1
        payload = {
            "ceilings": {"file_lines": FILE_CEILING, "function_lines": FUNCTION_CEILING},
            "python": f"allowances come from {ARCHITECTURE_BASELINE.as_posix()} (scripts/check_architecture.py)",
            "files": dict(sorted(current.items())),
        }
        (ROOT / BASELINE).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        stored = current
    errors = check(ROOT, python_allowances(ROOT), stored, base_ui_counts=base_counts)
    if errors:
        print("\n".join(errors))
        return 1
    print(summary(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
