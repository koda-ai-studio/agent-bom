"""Every shipped skill's frontmatter must be valid YAML; validators and hosts read it differently."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SKILLS = sorted((ROOT / "integrations").glob("**/skills/*/SKILL.md"))


def test_skills_are_discovered() -> None:
    assert len(SKILLS) >= 18


@pytest.mark.parametrize("path", SKILLS, ids=lambda path: str(path.relative_to(ROOT)))
def test_skill_frontmatter_parses_with_a_name_and_description(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    frontmatter = yaml.safe_load(text.split("---\n", 2)[1])
    assert isinstance(frontmatter, dict)
    assert frontmatter["name"]
    assert isinstance(frontmatter["description"], str)
