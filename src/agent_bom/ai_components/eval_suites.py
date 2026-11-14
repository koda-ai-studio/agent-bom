"""Detect eval suites in project files and link each to the agent or model it tests.

Supported harnesses: promptfoo configs, deepeval tests, ragas evaluations,
Inspect tasks, OpenAI evals (registry YAML and the Evals API) and LangSmith
datasets/evaluations. Detection only reads files: configs are parsed with
``yaml.safe_load`` and Python with ``ast``. Nothing is imported or run.

The result carries ``coverage`` — which project scopes were searched, how many
candidate files were read, and whether a limit stopped the search — so a
consumer can tell "no eval found in the scanned files" from "not searched".
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from agent_bom.ai_components.eval_config_parsers import (
    PROMPTFOO_FILENAMES,
    ConfigReadError,
    is_openai_evals_registry,
    parse_openai_evals_registry,
    parse_promptfoo,
)
from agent_bom.ai_components.eval_linking import AgentIndex
from agent_bom.ai_components.eval_models import EvalScanResult, EvalSuite
from agent_bom.ai_components.eval_python_parsers import PYTHON_MARKERS, parse_python_evals
from agent_bom.ai_components.project_scope import project_scope
from agent_bom.ast.source_reader import parse_python_source
from agent_bom.traversal import is_nested_worktree_root

__all__ = ["MAX_FILES_EXAMINED", "scan_eval_suites"]

logger = logging.getLogger(__name__)

# Same pruning as the framework-agent scan, so both passes cover the same files.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        ".env",
        "env",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".claude",
        ".codex",
    }
)
_MAX_FILE_BYTES = 512 * 1024
# Eval candidates parsed, and source files read, per scan; reaching either marks the search partial.
MAX_FILES_EXAMINED = 2000
MAX_FILES_READ = 20000


def scan_eval_suites(*paths: str | Path, framework_agents: list[dict[str, Any]] | None = None) -> EvalScanResult:
    """Read eval suites under ``paths``; ``framework_agents`` are the same scan's agents to link to."""
    result = EvalScanResult()
    agents = list(framework_agents or [])
    scopes: dict[str, Path] = {}
    for path in paths:
        root = Path(path)
        project_root = root if root.is_dir() else root.parent
        scope = project_scope(project_root.resolve(), scopes)
        if scope not in result.scopes:
            result.scopes.append(scope)
        index = AgentIndex(agents, scope)
        files = [root] if root.is_file() else _walk(root)
        read = 0
        for filepath in files:
            if not _is_candidate(filepath):
                continue
            if result.files_examined >= MAX_FILES_EXAMINED or read >= MAX_FILES_READ:
                result.partial_reason = f"eval-suite search stopped at its {MAX_FILES_EXAMINED}-candidate / {MAX_FILES_READ}-file limit"
                return result
            read += 1
            result.suites.extend(_read(project_root, filepath, index, scope, result))
    return result


def _walk(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in sorted(dirnames)
            if name not in _SKIP_DIRS and not name.endswith(".egg-info") and not is_nested_worktree_root(Path(dirpath) / name)
        ]
        files.extend(Path(dirpath) / name for name in sorted(filenames))
    return files


def _is_candidate(path: Path) -> bool:
    name = path.name.lower()
    return name in PROMPTFOO_FILENAMES or name.endswith(".py") or is_openai_evals_registry(path)


def _read(root: Path, path: Path, index: AgentIndex, scope: str, result: EvalScanResult) -> list[EvalSuite]:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        result.unreadable.append(_rel(root, path))
        return []
    is_python = path.suffix.lower() == ".py" and path.name.lower() not in PROMPTFOO_FILENAMES
    if is_python and not any(marker in text for marker in PYTHON_MARKERS):
        return []
    result.files_examined += 1
    try:
        if path.name.lower() in PROMPTFOO_FILENAMES:
            return parse_promptfoo(root, path, text, index, scope)
        if is_python:
            return parse_python_evals(root, path, parse_python_source(text, filename=str(path)), index, scope)
        return parse_openai_evals_registry(root, path, text, scope)
    except (ConfigReadError, SyntaxError, ValueError, RecursionError):
        logger.debug("eval candidate could not be parsed: %s", path, exc_info=True)
        result.unreadable.append(_rel(root, path))
        return []


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
