"""Which trust checks apply to a skill file, by the manifest format it uses.

ClawHub skill manifests declare ``file_reads``, ``requires.bins`` and the
persistence, telemetry and privilege-escalation fields. A Claude or Codex
SKILL.md, CLAUDE.md or AGENTS.md has none of them, so a check that only asks
whether one is present does not apply to that file.
"""

from __future__ import annotations

import dataclasses
import re
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
