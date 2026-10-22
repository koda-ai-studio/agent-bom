#!/usr/bin/env python3
"""Classify changed repository paths for fail-closed CI routing.

Documentation-only changes use a narrow fast path. Security routing separately
recognizes Python dependency inputs; ambiguous or unknown paths run
all security checks.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
from pathlib import Path, PurePosixPath
from typing import Iterable

_ROOT_DOCUMENTS = {
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "LICENSE.md",
    "NOTICE",
    "NOTICE.md",
    "README.md",
    "SECURITY.md",
    "mkdocs.yml",
}
_DOCUMENTATION_PREFIXES = (
    ".github/ISSUE_TEMPLATE/",
    "docs/",
    "site-docs/",
)


@dataclasses.dataclass(frozen=True)
class ChangeClassification:
    docs_only: bool
    changed_count: int
    python_dependencies: bool
    full_python: bool
    postgres_required: bool
    ui_container: bool


def _normalize_path(raw: str) -> str | None:
    value = raw.strip().replace("\\", "/")
    if not value or value.startswith("/"):
        return None
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _is_documentation_path(path: str) -> bool:
    if path in _ROOT_DOCUMENTS:
        return True
    if "/" not in path and path.lower().endswith(".md"):
        return True
    return path.startswith(_DOCUMENTATION_PREFIXES)


_KNOWN_PRODUCT_PREFIXES = (
    "src/",
    "tests/",
    "ui/",
    "sdks/",
    "scripts/",
    "deploy/",
    "integrations/",
    "examples/",
    "contracts/",
    ".clusterfuzzlite/fuzz/",
)
_PYTHON_DEPENDENCY_FILES = {
    "pyproject.toml",
    "uv.lock",
    "uv.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pdm.lock",
    ".python-version",
    "tox.ini",
}


def _python_dependency_path(path: str) -> bool:
    name = PurePosixPath(path).name
    return (
        name in _PYTHON_DEPENDENCY_FILES
        or bool(re.fullmatch(r"(?:requirements|constraints)(?:[-_.].*)?\.(?:txt|in)", name))
        or ("requirements" in PurePosixPath(path).parts and name.endswith((".txt", ".in")))
        or path.startswith((".github/workflows/", ".github/actions/", ".github/codeql/"))
        or path == "scripts/classify_ci_changes.py"
    )


def _known_path(path: str) -> bool:
    return _is_documentation_path(path) or _python_dependency_path(path) or path.startswith(_KNOWN_PRODUCT_PREFIXES)


def _shared_python_input(path: str) -> bool:
    """Foundations whose consumers span more than one selected domain."""
    return (
        path.startswith(("src/agent_bom/core/", "src/agent_bom/db/", "src/agent_bom/runtime/"))
        or path
        in {
            "scripts/pytest_ci_plan.py",
            "src/agent_bom/models.py",
            "src/agent_bom/canonical_ids.py",
            "src/agent_bom/graph_schema.py",
            "src/agent_bom/security.py",
            "src/agent_bom/rbac.py",
            "src/agent_bom/proxy.py",
            "src/agent_bom/gateway_server.py",
            "src/agent_bom/api/models.py",
            "src/agent_bom/api/server.py",
            "src/agent_bom/graph/correlation.py",
            "src/agent_bom/graph/rekey.py",
            "src/agent_bom/graph/edge.py",
        }
        or (
            path.startswith("tests/")
            and (not PurePosixPath(path).name.startswith("test_") or PurePosixPath(path).suffix != ".py" or "/fixtures/" in path)
        )
        or (path.startswith("src/") and PurePosixPath(path).name == "__init__.py")
    )


def _requires_full_python(paths: list[str], *, root: Path) -> bool:
    # This module is both imported by contracts and executed as a standalone
    # stdlib-only classifier before dependencies are installed.
    if __package__:
        from .pytest_ci_plan import AUTHORIZATION_SOURCES, select_targeted_tests
    else:
        from pytest_ci_plan import AUTHORIZATION_SOURCES, select_targeted_tests

    for path in paths:
        if _shared_python_input(path) or path in AUTHORIZATION_SOURCES:
            return True
        if path.startswith(("src/", "scripts/")):
            # Check each input independently: a mapped sibling must never hide
            # a new, deleted, or otherwise unmapped implementation surface.
            if not (root / path).is_file() or not select_targeted_tests(changed_files=[Path(path)], root=root):
                return True
    return False


def classify_paths(paths: Iterable[str]) -> ChangeClassification:
    """Return a narrow docs-only classification, failing closed on ambiguity."""
    raw_paths = list(paths)
    normalized = [_normalize_path(path) for path in raw_paths]
    valid_paths = [path for path in normalized if path is not None]
    docs_only = bool(valid_paths) and len(valid_paths) == len(raw_paths) and all(_is_documentation_path(path) for path in valid_paths)
    ambiguous = not valid_paths or len(valid_paths) != len(raw_paths) or any(not _known_path(path) for path in valid_paths)
    python_dependencies = ambiguous or any(_python_dependency_path(path) for path in valid_paths)
    full_python = python_dependencies or _requires_full_python(valid_paths, root=Path(__file__).resolve().parents[1])
    # Supplement the workflow's writer/migration ownership map with shared
    # model, authorization, storage and integration-test inputs.
    postgres_required = python_dependencies or any(
        path.startswith(("src/agent_bom/api/", "src/agent_bom/db/", "src/agent_bom/core/"))
        or path in {"src/agent_bom/models.py", "src/agent_bom/canonical_ids.py", "src/agent_bom/graph_schema.py", "src/agent_bom/rbac.py"}
        or (path.startswith("tests/") and ("postgres" in path or PurePosixPath(path).name == "conftest.py"))
        for path in valid_paths
    )
    ui_container = ambiguous or any(
        path.startswith((".github/workflows/", ".github/actions/setup-ui/", "ui/scripts/"))
        or path
        in {
            "ui/Dockerfile",
            "ui/docker-entrypoint.sh",
            "ui/.dockerignore",
            "ui/.npmrc",
            "ui/package.json",
            "ui/package-lock.json",
            "ui/.node-version",
            "ui/.nvmrc",
            "ui/tsconfig.json",
            "ui/postcss.config.mjs",
            "ui/next-env.d.ts",
            "ui/public/runtime-config.js",
            "ui/lib/runtime-config.ts",
        }
        or path.startswith("ui/next.config.")
        for path in valid_paths
    )
    return ChangeClassification(
        docs_only=docs_only,
        changed_count=len(valid_paths),
        python_dependencies=python_dependencies,
        full_python=full_python,
        postgres_required=postgres_required,
        ui_container=ui_container,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--github-output",
        help="Optional GitHub Actions output file to append classification values to.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    import sys

    classification = classify_paths(sys.stdin.read().splitlines())
    lines = "".join(
        f"{key}={str(value).lower() if isinstance(value, bool) else value}\n" for key, value in dataclasses.asdict(classification).items()
    )
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as output:
            output.write(lines)
    else:
        sys.stdout.write(lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
