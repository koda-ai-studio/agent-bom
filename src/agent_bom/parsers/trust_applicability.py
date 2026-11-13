"""Which trust checks apply to a skill file, by the manifest format it uses.

ClawHub skill manifests declare ``file_reads``, ``requires.bins`` and the
persistence, telemetry and privilege-escalation fields. A Claude or Codex
SKILL.md, CLAUDE.md or AGENTS.md has none of them, so a check that only asks
whether one is present does not apply to that file.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import PurePath
from typing import Any, TypeVar

CLAWHUB_MANIFEST_FIELDS = ("openclaw", "file_reads", "persistence", "telemetry", "privilege_escalation")

# Category levels that only a missing manifest field produces. Each category
# reaches these levels on no other path; findings raise FAIL instead.
_MANIFEST_GAP_LEVELS = {
    "purpose_capability": {"info"},
    "instruction_scope": {"warn", "info"},
    "persistence_privilege": {"warn", "info"},
}

CategoryT = TypeVar("CategoryT")


def declares_clawhub_manifest(raw_frontmatter: str) -> bool:
    return any(re.search(rf"^\s*{name}\s*:", raw_frontmatter, re.MULTILINE) for name in CLAWHUB_MANIFEST_FIELDS)


def apply_manifest_applicability(categories: list[CategoryT], raw_frontmatter: str, pass_level: Any) -> list[CategoryT]:
    """Pass the manifest-only checks of a file that declares no ClawHub manifest, saying why."""
    if declares_clawhub_manifest(raw_frontmatter):
        return categories
    return [_not_applicable(c, pass_level) if _is_manifest_gap(c) else c for c in categories]


def _is_manifest_gap(category: Any) -> bool:
    return str(category.level.value) in _MANIFEST_GAP_LEVELS.get(category.key, set())


def _not_applicable(category: Any, pass_level: Any) -> Any:
    summary = f"Not applicable without a ClawHub manifest: {category.summary}"
    return dataclasses.replace(category, level=pass_level, summary=summary)


# A prompt file with no skill metadata is not a skill package: it has no
# manifest to declare a name, binaries, an install method or a source, so
# these gaps say nothing about it. Content findings still raise FAIL.
_PROMPT_FILE_GAP_LEVELS = {
    **_MANIFEST_GAP_LEVELS,
    "purpose_capability": {"warn", "info"},
    "install_mechanism": {"fail", "warn", "info"},
}


def is_plain_prompt_file(source_files: list[str], has_metadata: bool) -> bool:
    """No skill metadata and no SKILL.md among the files: instructions, not a skill package."""
    if has_metadata or not source_files:
        return False
    return not any(PurePath(str(path)).name.lower() == "skill.md" for path in source_files)


def apply_prompt_file_applicability(categories: list[CategoryT], note_level: Any) -> list[CategoryT]:
    """Downgrade the skill-manifest gaps of a plain prompt file to a note saying they do not apply."""
    return [_prompt_not_applicable(c, note_level) if _is_prompt_gap(c) else c for c in categories]


def _is_prompt_gap(category: Any) -> bool:
    return str(category.level.value) in _PROMPT_FILE_GAP_LEVELS.get(category.key, set())


def _prompt_not_applicable(category: Any, note_level: Any) -> Any:
    summary = category.summary.removeprefix("Not applicable without a ClawHub manifest: ")
    return dataclasses.replace(category, level=note_level, summary=f"Not applicable to a prompt file without skill metadata: {summary}")


def applicable_categories(
    categories: list[CategoryT], meta: Any, source_files: list[str], pass_level: Any, note_level: Any
) -> tuple[list[CategoryT], bool]:
    """Apply both applicability rules; also say whether the files are a plain prompt, whose provenance stays unverified."""
    categories = apply_manifest_applicability(categories, meta.raw_frontmatter if meta else "", pass_level)
    plain_prompt = is_plain_prompt_file(source_files, meta is not None)
    return (apply_prompt_file_applicability(categories, note_level) if plain_prompt else categories), plain_prompt
