"""Claude Code skill frontmatter grants and directive-vs-documentation calibration."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.skills_service import scan_skill_targets

_META = "description: Helper.\nhomepage: https://example.org/h\nsource: https://example.org/h\nlicense: MIT\n"


def _audit(tmp_path: Path, frontmatter: str, body: str = "Summarise the diff for the user.\n"):
    skill = tmp_path / "helper" / "SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text(f"---\nname: helper\n{_META}{frontmatter}---\n\n{body}")
    return scan_skill_targets([skill]).files[0].audit.findings


def _by_category(findings, category):
    return [f for f in findings if f.category == category]


@pytest.mark.parametrize(
    "grant",
    [
        "allowed-tools: Read, Grep, Glob\n",
        "allowed-tools: Read Grep Glob\n",
        "allowed-tools: [Read, Grep, Glob]\n",
        "allowed-tools:\n  - Read\n  - Grep\n",
        'allowed-tools: "Bash(git diff:*), Read"\n',
    ],
)
def test_allowed_tools_is_a_capability_declaration(tmp_path, grant):
    findings = _audit(tmp_path, grant)
    assert _by_category(findings, "missing_capability_declaration") == []
    assert _by_category(findings, "broad_tool_grant") == []


def test_skill_without_any_declaration_still_warns(tmp_path):
    findings = _audit(tmp_path, "")
    assert len(_by_category(findings, "missing_capability_declaration")) == 1


@pytest.mark.parametrize(
    "grant, severity, evidence",
    [
        ("allowed-tools: Bash\n", "medium", "Bash"),
        ("allowed-tools: Bash(*), Read\n", "medium", "Bash(*)"),
        ("allowed-tools:\n  - Read\n  - Bash(:*)\n", "medium", "Bash(:*)"),
        ("allowed-tools: Read, WebFetch, Write\n", "medium", "WebFetch"),
        ("allowed-tools: Bash(*), Write, WebFetch\n", "medium", "execute-and-egress"),
    ],
)
def test_broad_grants_are_flagged_with_evidence(tmp_path, grant, severity, evidence):
    findings = _audit(tmp_path, grant)
    broad = _by_category(findings, "broad_tool_grant")
    assert len(broad) == 1
    assert broad[0].severity == severity
    assert evidence in broad[0].detail
    assert broad[0].context == "metadata"
    assert _by_category(findings, "missing_capability_declaration") == []


def test_scoped_shell_grant_is_not_broad(tmp_path):
    findings = _audit(tmp_path, "allowed-tools: Bash(npm test:*), Bash(git status), Read, Write\n")
    assert _by_category(findings, "broad_tool_grant") == []
