"""Skill commands quote every substituted value and refuse unsafe ones."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CODEX = ROOT / "integrations" / "codex" / "skills"
CLAUDE = ROOT / "integrations" / "claude-code" / "skills"
CODEX_SKILLS = sorted(CODEX.glob("*/SKILL.md"))
SHELL_SKILLS = [*CODEX_SKILLS, CLAUDE / "bom" / "SKILL.md"]
CHARSET = "[A-Za-z0-9@/._:+~-]"
_SPAN = re.compile(r"`([^`]+)`")
_PLACEHOLDER = re.compile(r"<[a-z-]+>|<N>")


def _command_spans(text: str) -> list[str]:
    # `npx -y <package>` and `uvx <package>` describe launchers found in a config; they are never run.
    spans = [span for span in _SPAN.findall(text) if not span.startswith(("npx ", "uvx <"))]
    return [span for span in spans if span.startswith(("uvx ", "-")) or " -" in span]


@pytest.mark.parametrize("skill", SHELL_SKILLS, ids=lambda p: f"{p.parents[2].name}/{p.parent.name}")
def test_every_substituted_argument_is_single_quoted(skill: Path) -> None:
    for span in _command_spans(skill.read_text(encoding="utf-8")):
        for word in span.split():
            if _PLACEHOLDER.search(word):
                assert word.startswith("'") and word.endswith("'"), f"{skill.parent.name}: unquoted {word!r} in `{span}`"


@pytest.mark.parametrize("skill", SHELL_SKILLS, ids=lambda p: f"{p.parents[2].name}/{p.parent.name}")
def test_shell_skills_refuse_values_outside_the_safe_charset(skill: Path) -> None:
    rules = skill.read_text(encoding="utf-8").split("\n## Rules\n", 1)[1]
    assert CHARSET in rules
    assert "`check`" in rules, "names from untrusted output must be validated before suggesting check"


@pytest.mark.parametrize("skill", CODEX_SKILLS, ids=lambda p: p.parent.name)
def test_codex_skills_do_not_point_to_the_mcp_workspace_setting(skill: Path) -> None:
    assert "AGENT_BOM_MCP_WORKSPACE_ROOTS" not in skill.read_text(encoding="utf-8")


def test_mcp_skills_keep_the_workspace_roots_rule() -> None:
    for skill in sorted(CLAUDE.glob("*/SKILL.md")):
        assert "AGENT_BOM_MCP_WORKSPACE_ROOTS" in skill.read_text(encoding="utf-8"), skill.parent.name
