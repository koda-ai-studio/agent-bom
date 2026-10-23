"""Docs and skills may only cite agent-bom commands that the CLI registers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_skill_cli_citations.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_skill_cli_citations", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


citations = _load()

# Groups map to their children; leaf commands map to None.
TREE = {
    "skills": {"scan": None, "verify": None},
    "cloud": {"aws": None, "inventory": None},
    "check": None,
    "runtime": {"configure": None, "audit": None},
}


@pytest.mark.parametrize(
    "command",
    [
        "agent-bom skills scan .",
        "uvx agent-bom check flask@2.0.0 --ecosystem pypi",
        "agent-bom skills --help",
        "agent-bom skills",
        "agent-bom runtime configure --apply",
        "agent-bom cloud <provider>",
        "agent-bom check requests | jq .",
    ],
)
def test_registered_commands_pass(command: str) -> None:
    assert citations.invalid_reason(command, TREE) is None


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ("agent-bom skills audit .", "skills audit"),
        ("agent-bom cloud model-provenance org/model", "cloud model-provenance"),
        ("agent-bom proxy-configure --apply", "proxy-configure"),
        ("agent-bom blast-radius --cve CVE-2024-0001", "blast-radius"),
    ],
)
def test_unregistered_subcommands_fail_with_the_missing_path(command: str, reason: str) -> None:
    assert citations.invalid_reason(command, TREE) == reason


def test_docs_citations_come_from_code_spans_only() -> None:
    text = "\n".join(
        [
            "agent-bom receives sanitized inventory in prose.",
            "Run `agent-bom skills audit` next.",
            "```bash",
            "$ agent-bom cloud model-provenance x",
            "agent-bom check flask",
            "```",
        ]
    )
    assert list(citations.commands_in(text)) == [
        "agent-bom cloud model-provenance x",
        "agent-bom check flask",
        "agent-bom skills audit",
    ]


def test_scanned_paths_cover_docs_site_docs_and_skills() -> None:
    rels = {path.relative_to(citations.ROOT).as_posix() for path in citations.citation_paths()}
    assert "docs/MCP_SECURITY_MODEL.md" in rels
    assert "site-docs/reference/exit-codes.md" in rels
    assert "integrations/openclaw/SKILL.md" in rels


def test_repository_docs_cite_only_registered_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert citations.main() == 0, capsys.readouterr().err
