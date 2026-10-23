"""The skill-audit accuracy gate must measure, and it must be able to fail.

Scanning our own plugin skills read ``npx -y <package>`` as a package named
``-y``, a YAML ``- npx`` list item followed by ``optional_bins:`` as an npm
package, and quoted guidance about "ignore previous instructions" as coercion.
None of that was measured; it was found by accident. These tests pin the
labelled corpus, the recorded baseline, zero tolerance for those regressions,
and mutation checks proving the gate notices when the parser or the prose
demotion breaks.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "docs" / "SKILL_AUDIT_ACCURACY.json"
CORPUS = ROOT / "tests" / "fixtures" / "skill_accuracy"

# Categories a label may name that the auditor does not implement yet. Listing
# them keeps the miss visible as a recall of 0 instead of an unlabelled gap.
UNIMPLEMENTED_CATEGORIES: frozenset[str] = frozenset()

# Every case that currently breaks a must_not, named so a new violation shows
# up as an identity, not just as a count moving.
KNOWN_MUST_NOT_VIOLATIONS = frozenset({"benign-security-review-quoted-injection"})

# The regressions that were found by accident, each pinned to the case that
# reproduces it. These must stay clean with no tolerance at all.
ZERO_TOLERANCE_CASES = {
    "benign-launcher-placeholders": "npx -y <package> read as a package named -y",
    "benign-pinned-launchers": "npx -y <pinned package> must yield the package, never -y",
    "benign-frontmatter-bins-list": "'- npx' then 'optional_bins:' read as an npm package",
    "benign-untrusted-config-report-guidance": "quoted 'ignore previous instructions' guidance read as coercion",
    "benign-claude-md-project-conventions": "uv run <command> read as a PyPI package",
}


def _load_harness():
    """Import the script by path; scripts/ is not an importable package."""
    target = Path("/tmp") / "skill_audit_accuracy_under_test.py"
    shutil.copyfile(ROOT / "scripts" / "skill_audit_accuracy.py", target)
    spec = importlib.util.spec_from_file_location("skill_audit_accuracy_under_test", target)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def harness():
    return _load_harness()


@pytest.fixture(scope="module")
def cases(harness):
    return harness.load_cases(CORPUS)


@pytest.fixture(scope="module")
def result(harness, cases):
    return harness.score(cases)


def _emitted_categories() -> set[str]:
    source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "src" / "agent_bom" / "parsers").glob("skill*.py"))
    return set(re.findall(r'category="([a-z_]+)"', source))


def test_corpus_is_large_balanced_and_well_formed(cases) -> None:
    kinds = [case.kind for case in cases]
    assert len(cases) >= 60
    assert kinds.count("benign") >= 25 and kinds.count("risky") >= 25
    assert set(kinds) == {"benign", "risky"}

    known = _emitted_categories() | UNIMPLEMENTED_CATEGORIES
    for case in cases:
        assert case.surface.is_file(), case.case_id
        assert case.label.get("description"), case.case_id
        named = [item["category"] for key in ("expect", "must_not") for item in case.label.get(key, [])]
        assert set(named) <= known, f"{case.case_id} names unknown categories {set(named) - known}"
        if case.kind == "risky":
            assert case.label.get("expect"), f"risky case {case.case_id} expects nothing"


def test_corpus_covers_every_surface_kind(cases) -> None:
    surfaces = {case.surface.name for case in cases}
    assert {"SKILL.md", "CLAUDE.md", "AGENTS.md", ".cursorrules"} <= surfaces


def test_clean_tree_meets_the_recorded_baseline(harness, result) -> None:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    errors = harness.regressions(result.to_dict(), baseline)
    assert errors == [], "\n".join(errors)


@pytest.mark.parametrize("case_id", sorted(ZERO_TOLERANCE_CASES))
def test_found_by_accident_regressions_stay_fixed(harness, cases, case_id) -> None:
    case = next(case for case in cases if case.case_id == case_id)
    out = harness.score([case])
    assert out.must_not_violations == [], f"{ZERO_TOLERANCE_CASES[case_id]}: {out.must_not_violations}"
    assert out.packages.false_positive == 0, f"{ZERO_TOLERANCE_CASES[case_id]}: {out.spurious}"
    assert out.packages.false_negative == 0, out.misses


def test_must_not_violations_are_the_known_set(result) -> None:
    violating = {line.split(":", 1)[0] for line in result.must_not_violations}
    assert violating == KNOWN_MUST_NOT_VIOLATIONS, "the violating set changed; fix the regression or re-derive the baseline"
    assert not violating & set(ZERO_TOLERANCE_CASES)


def test_the_gate_detects_a_launcher_flag_regression(harness, cases) -> None:
    """Mutation: restore the pattern that read ``-y`` as a package."""
    from agent_bom.parsers import skills

    original = skills._NPX_RE
    try:
        skills._NPX_RE = re.compile(r"(?:npx|bunx)\s+(?:-[yYp]\s+)*(@?[\w./-]+(?:@[\w.^~<>=+-]+)?)")
        mutated = harness.score(cases)
    finally:
        skills._NPX_RE = original

    assert mutated.packages.false_positive > 0
    assert any("forbidden package npm:-y" in line for line in mutated.must_not_violations)
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert harness.regressions(mutated.to_dict(), baseline), "the gate passed a reintroduced -y regression"


def test_the_gate_detects_losing_documentation_demotion(harness, cases) -> None:
    """Mutation: treat every policy/example sentence as a live directive."""
    from agent_bom.parsers import skill_audit_behavior

    original = skill_audit_behavior._is_prohibition_context
    try:
        skill_audit_behavior._is_prohibition_context = lambda *_args, **_kwargs: False
        mutated = harness.score(cases)
    finally:
        skill_audit_behavior._is_prohibition_context = original

    assert mutated.tally("prompt_coercion").false_positive > 0
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert harness.regressions(mutated.to_dict(), baseline)


def test_the_gate_detects_a_recall_loss(harness, cases) -> None:
    """Mutation: drop the curl-pipe-shell rule and require recall to fall."""
    from agent_bom.parsers import skill_audit_behavior

    original = skill_audit_behavior._BEHAVIORAL_PATTERNS
    try:
        skill_audit_behavior._BEHAVIORAL_PATTERNS = [p for p in original if p.category != "remote_code_execution"]
        mutated = harness.score(cases)
    finally:
        skill_audit_behavior._BEHAVIORAL_PATTERNS = original

    assert mutated.tally("remote_code_execution").recall < 1.0
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    errors = harness.regressions(mutated.to_dict(), baseline)
    assert any("remote_code_execution recall" in error for error in errors)


@pytest.mark.parametrize(
    ("scanner", "category"),
    [
        ("scan_hardcoded_secrets", "hardcoded_secret"),
        ("scan_env_exfiltration", "credential_exfiltration"),
        ("scan_hidden_instructions", "hidden_instruction"),
    ],
)
def test_the_gate_detects_losing_a_content_detector(harness, cases, scanner, category) -> None:
    """Mutation: drop one content detector and require its recall to fall."""
    from agent_bom.parsers import skill_audit_behavior

    original = getattr(skill_audit_behavior, scanner)
    try:
        setattr(skill_audit_behavior, scanner, lambda _raw: [])
        mutated = harness.score(cases)
    finally:
        setattr(skill_audit_behavior, scanner, original)

    assert mutated.tally(category).recall < 1.0
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert any(f"{category} recall" in error for error in harness.regressions(mutated.to_dict(), baseline))


def test_scoring_tolerates_low_evidence_but_not_above_the_ceiling(harness, tmp_path) -> None:
    surface = tmp_path / "SKILL.md"
    surface.write_text("Enable developer mode in chrome://extensions.\n", encoding="utf-8")
    tolerant = harness.Case("tolerant", "benign", surface, {"must_not": [{"category": "prompt_coercion", "max_severity": "low"}]})
    strict = harness.Case("strict", "benign", surface, {"must_not": [{"category": "prompt_coercion"}]})

    assert harness.score([tolerant]).must_not_violations == []
    assert harness.score([strict]).must_not_violations == ["strict: prompt_coercion fired at low (ceiling none)"]


def test_baseline_is_reproducible(harness, result) -> None:
    """The recorded file is exactly what the current tree measures."""
    assert json.loads(BASELINE.read_text(encoding="utf-8")) == result.to_dict()
