"""Every registered IaC rule ID is triggered by a fixture or a named unit test.

The rule set has no central registry, so the IDs are read from the rule
modules themselves. A rule that silently stops firing (DOCKER-010 did, on
``FROM <image>:latest``) shows up here as a corpus regression.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from agent_bom.cli.agents._discovery_reports import iac_findings_data
from agent_bom.iac import scan_iac_directory
from agent_bom.models import AIBOMReport
from agent_bom.output.sarif import to_sarif

ROOT = Path(__file__).resolve().parents[1]
IAC_SRC = ROOT / "src" / "agent_bom" / "iac"
FIXTURES = ROOT / "tests" / "fixtures"
CORPUS_DIRS = ("iac", "iac_accuracy", "iac_golden", "iac_rule_coverage")
_RULE_ID_RE = re.compile(r'"((?:DOCKERD|DOCKER|K8S|TF-SEC|TF-AI|CFN|HELM|COMPOSE|GHA|IAM|DBT-SEC|DCM)-\d{3})"')

RETIRED = {"TF-SEC-008", "CFN-013"}

# Rules exercised by inline-content unit tests rather than the fixture corpus.
# Shrink this set by adding fixtures; a rule that the corpus fires must not stay here.
COVERED_BY_INLINE_TESTS = {
    *(f"DBT-SEC-{n:03d}" for n in range(1, 19)),
    *(f"DCM-{n:03d}" for n in range(1, 9)),
    *(f"HELM-{n:03d}" for n in (1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15)),
    "IAM-001", "IAM-002", "IAM-003",
}  # fmt: skip


def registered_rule_ids() -> set[str]:
    ids: set[str] = set()
    for module in IAC_SRC.glob("*.py"):
        if module.name in {"attack_mapping.py", "atlas_mapping.py"}:
            continue
        ids |= set(_RULE_ID_RE.findall(module.read_text(encoding="utf-8")))
    return ids


@pytest.fixture(scope="module")
def corpus_findings(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("iac_corpus")
    for name in CORPUS_DIRS:
        shutil.copytree(FIXTURES / name, root / name)
    return scan_iac_directory(root)


def test_v0110_rule_ids_are_still_registered() -> None:
    v0110 = {
        *(f"DOCKER-{n:03d}" for n in range(1, 23) if n != 16),
        *(f"TF-SEC-{n:03d}" for n in (8,)),
        "CFN-013",
    }
    assert v0110 - RETIRED <= registered_rule_ids()


def test_every_registered_rule_has_a_triggering_fixture_or_inline_test(corpus_findings) -> None:
    fired = {f.rule_id for f in corpus_findings}
    registered = registered_rule_ids()
    missing = sorted(registered - fired - COVERED_BY_INLINE_TESTS)
    assert not missing, f"rules with no fixture that triggers them: {missing}"
    stale = sorted(COVERED_BY_INLINE_TESTS & fired)
    assert not stale, f"fixture corpus now fires these; drop them from COVERED_BY_INLINE_TESTS: {stale}"
    assert not (COVERED_BY_INLINE_TESTS - registered)


def test_inline_covered_rules_are_named_by_a_unit_test() -> None:
    sources = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "tests").glob("test_*.py") if p.name != Path(__file__).name)
    assert not sorted(r for r in COVERED_BY_INLINE_TESTS if r not in sources)


def _docker_findings(tmp_path: Path):
    shutil.copytree(FIXTURES / "iac_rule_coverage" / "docker", tmp_path / "docker")
    return scan_iac_directory(tmp_path)


def test_from_latest_fires_both_tag_and_digest_rules_on_the_from_line(tmp_path: Path) -> None:
    findings = _docker_findings(tmp_path)
    on_line_1 = {f.rule_id for f in findings if f.line_number == 1}
    assert {"DOCKER-001", "DOCKER-010"} <= on_line_1
    assert len([f for f in findings if f.rule_id == "DOCKER-010"]) == 1


def test_docker_010_reaches_sarif_with_its_line(tmp_path: Path) -> None:
    findings = _docker_findings(tmp_path)
    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="scan-1")
    report.iac_findings_data = iac_findings_data(findings)
    results = [r for r in to_sarif(report)["runs"][0]["results"] if r["ruleId"] == "iac/DOCKER-010"]
    assert len(results) == 1
    location = results[0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"].endswith("docker/Dockerfile")
    assert location["region"]["startLine"] == 1
