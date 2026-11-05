"""Directory packages must not expose a coding-agent transcript reader."""

from pathlib import Path

from agent_bom.mcp_tools.profiles import get_profile

ROOT = Path(__file__).resolve().parents[1]


def test_directory_profiles_and_skills_exclude_activity():
    assert "agent_activity" not in get_profile("audit").tools
    for package in ("claude-code", "codex"):
        assert not (ROOT / "integrations" / package / "skills" / "activity").exists()
