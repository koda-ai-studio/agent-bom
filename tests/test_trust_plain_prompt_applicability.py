"""A plain prompt file is not a skill: skill-manifest checks do not fail or warn on it."""

from __future__ import annotations

from pathlib import Path

from agent_bom.parsers.skill_audit import audit_skill_result
from agent_bom.parsers.skills import scan_skill_files
from agent_bom.parsers.trust_assessment import ProvenanceVerdict, ReviewVerdict, TrustLevel, assess_trust

_PROMPT = """# First-run support agent

You help a developer understand the local sample project. Stay inside the
workspace, cite the file you inspected, and do not request or print secret
values.
"""


def _assess(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    scan = scan_skill_files([path])
    return assess_trust(scan, audit_skill_result(scan))


def test_plain_prompt_file_gets_no_manifest_fail_or_warn(tmp_path: Path) -> None:
    result = _assess(tmp_path / "prompts" / "agent-system-prompt.md", _PROMPT)
    levels = {category.key: category.level for category in result.categories}
    assert levels["install_mechanism"] == TrustLevel.INFO
    assert levels["purpose_capability"] == TrustLevel.INFO
    assert all(category.level not in (TrustLevel.FAIL, TrustLevel.WARN) for category in result.categories)
    install = next(c for c in result.categories if c.key == "install_mechanism")
    assert install.summary.startswith("Not applicable to a prompt file without skill metadata")
    # Nothing about its origin can be verified, so it still asks for review.
    assert result.provenance_verdict == ProvenanceVerdict.UNVERIFIED
    assert result.review_verdict == ReviewVerdict.REVIEW


def test_skill_md_without_metadata_still_gets_manifest_checks(tmp_path: Path) -> None:
    result = _assess(tmp_path / "skills" / "helper" / "SKILL.md", _PROMPT)
    levels = {category.key: category.level for category in result.categories}
    assert levels["install_mechanism"] == TrustLevel.FAIL
    assert levels["purpose_capability"] == TrustLevel.WARN
