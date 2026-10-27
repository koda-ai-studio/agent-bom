#!/usr/bin/env python3
"""Select the pytest modules a pull request affects.

The selection is the changed-domain map from ``pytest_ci_plan.py targeted``
plus every test module that directly imports, loads or references a changed
input: source and script modules (including package ``__init__``), shared test
helpers, ``conftest.py`` (every module below it) and fixture data. Only direct
references count; the full suite runs after merge and nightly.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path, PurePosixPath
from typing import Iterable

if __package__:
    from .pytest_ci_plan import discover_test_files, estimate_seconds, load_durations, select_targeted_tests
else:
    from pytest_ci_plan import discover_test_files, estimate_seconds, load_durations, select_targeted_tests


SMOKE_TESTS = (
    "tests/test_ci_workflow_contract.py",
    "tests/test_runtime_child_span_redaction.py",
    "tests/test_doc_architecture_svgs.py",
    "tests/test_public_frontdoor_contract.py",
    "tests/test_public_release_contracts.py",
    "tests/test_cli_cold_start.py",
    "tests/test_docs_toolchain.py",
    "tests/test_public_docs_cli_alignment.py",
    "tests/test_readme_demo_excerpt.py",
    "tests/test_cli_entry_points.py",
    "tests/test_product_surface_contract.py",
    "tests/api/test_api_scan_findings_wiring.py",
    "tests/api/test_live_export_contracts.py",
)


def _module_patterns(path: PurePosixPath) -> tuple[str, list[re.Pattern[str]]]:
    """Return a cheap prefilter token and the import/reference patterns for a Python file."""
    parts = list(path.with_suffix("").parts)
    if parts[0] == "src":
        parts = parts[1:]
    package = parts[-1] == "__init__"
    if package:
        parts = parts[:-1]
    dotted = re.escape(".".join(parts))
    leaf = parts[-1]
    patterns = [re.compile(rf"\b{dotted}\b" + (r"(?![\w.])" if package else ""))]
    if len(parts) > 1:
        parent = re.escape(".".join(parts[:-1]))
        patterns.append(re.compile(rf"from\s+{parent}\s+import\s+(?:\([^)]*\b{re.escape(leaf)}\b[^)]*\)|[^\n]*\b{re.escape(leaf)}\b)"))
    if path.parts[0] in {"scripts", "tests"} and not package:
        patterns.append(re.compile(rf"^\s*(?:from|import)\s+{re.escape(leaf)}\b", re.MULTILINE))
        patterns.append(re.compile(rf"\b{re.escape(path.name)}\b"))
    return leaf, patterns


def _fixture_patterns(path: PurePosixPath) -> tuple[str, list[re.Pattern[str]]]:
    """Reference patterns for a non-Python file below ``tests/``."""
    patterns = [re.compile(rf"(?<![\w.-]){re.escape(path.name)}\b")]
    parts = path.parts
    if "fixtures" in parts[:-1]:
        index = parts.index("fixtures")
        if index + 1 < len(parts) - 1:
            directory = re.escape(parts[index + 1])
            patterns.append(re.compile(rf"""["'/]{directory}["'/]"""))
            return parts[index + 1], patterns
    return path.name, patterns


def _references(changed: PurePosixPath) -> tuple[str, list[re.Pattern[str]]] | None:
    top = changed.parts[0] if changed.parts else ""
    if changed.suffix == ".py":
        if top in {"src", "scripts"} or (top == "tests" and not changed.name.startswith("test_") and changed.name != "conftest.py"):
            return _module_patterns(changed)
        return None
    if top == "tests":
        return _fixture_patterns(changed)
    return None


def select_affected_tests(*, changed_files: Iterable[Path], root: Path) -> list[Path]:
    """Return the changed-domain selection plus direct importers/referrers of each changed input."""
    changed = [Path(path.as_posix().removeprefix("./")) for path in changed_files]
    selected = set(select_targeted_tests(changed_files=changed, root=root))
    available = discover_test_files(root / "tests")
    texts: dict[Path, str] = {}

    def text(candidate: Path) -> str:
        if candidate not in texts:
            texts[candidate] = candidate.read_text(encoding="utf-8", errors="replace")
        return texts[candidate]

    for path in changed:
        posix = PurePosixPath(path.as_posix())
        if posix.name == "conftest.py" and posix.parts[0] == "tests":
            scope = root / posix.parent
            selected.update(candidate for candidate in available if candidate.is_relative_to(scope))
            continue
        references = _references(posix)
        if references is None:
            continue
        token, patterns = references
        selected.update(
            candidate
            for candidate in available
            if token in text(candidate) and any(pattern.search(text(candidate)) for pattern in patterns)
        )
    return sorted(selected)


def affected_shard_count(files: Iterable[Path], *, durations: dict[Path, float], target_seconds: float = 900) -> int:
    """Size runners by worker-seconds without discarding any affected module.

    The 900 worker-second target leaves setup and contention headroom in the
    15-minute job bound. Missing timings use the maximum bounded fan-out.
    This is an estimate, not a promise that an indivisible slow module fits.
    """
    files = sorted(set(files))
    if not files:
        raise ValueError("affected selection is empty")
    if not math.isfinite(target_seconds) or target_seconds <= 0:
        raise ValueError("target seconds must be finite and positive")
    maximum = min(12, len(files))
    seconds = sum(estimate_seconds(files, durations).values())
    return min(maximum, max(1, math.ceil(seconds / target_seconds))) if seconds else maximum


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    parser.add_argument("--matrix", action="store_true", help="print duration-sized shard indices as JSON")
    parser.add_argument("--include-smoke", action="store_true", help="include mandatory contract modules")
    parser.add_argument("changed_files", nargs="*", type=Path)
    args = parser.parse_args()
    cwd = Path.cwd().resolve()
    root = args.root.resolve()
    selected = set(select_affected_tests(changed_files=args.changed_files, root=root))
    if args.include_smoke:
        selected.update(root / path for path in SMOKE_TESTS)
    if args.matrix:
        count = affected_shard_count(selected, durations=load_durations(root / "tests/.ci-durations.json"))
        print(json.dumps(list(range(count))))
        return 0
    for path in sorted(selected):
        resolved = path.resolve()
        print(resolved.relative_to(cwd).as_posix() if resolved.is_relative_to(cwd) else resolved.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
