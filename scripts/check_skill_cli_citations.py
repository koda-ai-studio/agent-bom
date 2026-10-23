#!/usr/bin/env python3
"""Validate executable agent-bom command citations in shipped skills and docs.

Only fenced code blocks and inline code spans are treated as executable
citations. This avoids false positives from prose such as "agent-bom receives
sanitized inventory".

Every word after ``agent-bom`` must resolve through the click command tree
until a leaf command, an option, a placeholder or a shell operator. Skills
must cite visible commands; docs may also cite hidden compatibility commands
that are still registered.
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path
from typing import Iterable, Optional, Union

ROOT = Path(__file__).resolve().parents[1]
SKILL_GLOBS = ("integrations/**/SKILL.md",)
DOC_GLOBS = ("docs/**/*.md", "site-docs/**/*.md", "README.md", "integrations/**/README.md")
# Historical records describe commands as they were at the time.
DOC_EXCLUDE_PREFIXES = ("docs/archive/", "docs/releases/", "site-docs/releases/")
_FENCED_BLOCK_RE = re.compile(r"```([a-zA-Z0-9_-]*)\n(.*?)```", re.DOTALL)
# Fences that show program output rather than commands to run.
_OUTPUT_FENCES = {"text", "log", "output", "plaintext"}
_INLINE_CODE_RE = re.compile(r"`([^`\n]*agent-bom[^`\n]*)`")
_STOP_TOKENS = {"|", "||", "&&", ";", ">", ">>", "\\", "2>&1"}

# A group maps subcommand names to nodes; a leaf command is None.
Tree = dict[str, Optional["Tree"]]
Node = Union[Tree, None]


def command_tree(*, include_hidden: bool) -> Tree:
    sys.path.insert(0, str(ROOT / "src"))
    from agent_bom.cli import main as cli_main

    def walk(command: object) -> Node:
        children = getattr(command, "commands", None)
        if children is None:
            return None
        return {name: walk(child) for name, child in children.items() if include_hidden or not getattr(child, "hidden", False)}

    tree = walk(cli_main)
    assert isinstance(tree, dict)
    return tree


def _is_doc(path: Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    return not rel.startswith(DOC_EXCLUDE_PREFIXES) and "/node_modules/" not in f"/{rel}"


def skill_paths() -> list[Path]:
    paths: set[Path] = set()
    for pattern in SKILL_GLOBS:
        paths.update(ROOT.glob(pattern))
    return sorted(paths)


def citation_paths() -> list[Path]:
    paths = set(skill_paths())
    for pattern in DOC_GLOBS:
        paths.update(path for path in ROOT.glob(pattern) if path.is_file() and _is_doc(path))
    return sorted(paths)


def _commands_from_fenced_blocks(text: str) -> Iterable[str]:
    for language, block in _FENCED_BLOCK_RE.findall(text):
        if language.lower() in _OUTPUT_FENCES:
            continue
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith(("$ ", "# ")):
                stripped = stripped[2:].strip()
            if stripped.startswith("agent-bom ") or stripped.startswith("uvx agent-bom "):
                yield stripped


def _commands_from_inline_code(text: str) -> Iterable[str]:
    for match in _INLINE_CODE_RE.findall(text):
        stripped = match.strip()
        if stripped.startswith("agent-bom ") or stripped.startswith("uvx agent-bom "):
            yield stripped


def commands_in(text: str) -> Iterable[str]:
    yield from _commands_from_fenced_blocks(text)
    # Fenced blocks are matched first; remove them so inline spans inside a
    # block are not read twice.
    yield from _commands_from_inline_code(_FENCED_BLOCK_RE.sub("", text))


def _command_tokens(command: str) -> list[str]:
    try:
        tokens = shlex.split(command, comments=True)
    except ValueError:
        tokens = command.split()
    if tokens[:2] == ["uvx", "agent-bom"]:
        return tokens[2:]
    if tokens[:1] == ["agent-bom"]:
        return tokens[1:]
    return []


def invalid_reason(command: str, tree: Tree) -> str | None:
    """The unresolved command path, or None when the citation resolves."""
    tokens = _command_tokens(command)
    if not tokens or not re.match(r"^[a-z]", tokens[0]):
        return None
    node: Node = tree
    path: list[str] = []
    for token in tokens:
        if node is None or token.startswith(("-", "<", "[", "$", "{", "(", "...", "…")) or token in _STOP_TOKENS:
            return None
        path.append(token)
        if token not in node:
            return " ".join(path)
        node = node[token]
    return None


def main() -> int:
    visible = command_tree(include_hidden=False)
    registered = command_tree(include_hidden=True)
    skills = set(skill_paths())
    failures: list[str] = []
    for path in citation_paths():
        tree = visible if path in skills else registered
        text = path.read_text(encoding="utf-8")
        for command in commands_in(text):
            reason = invalid_reason(command, tree)
            if reason:
                failures.append(f"{path.relative_to(ROOT)}: `agent-bom {reason}` is not a command: `{command}`")

    if failures:
        print("check_skill_cli_citations: stale agent-bom command citations found:", file=sys.stderr)
        print("\n".join(f"  - {failure}" for failure in sorted(set(failures))), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
