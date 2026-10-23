#!/usr/bin/env python3
"""Measure skill / instruction-file audit precision and recall on a labelled corpus.

The skill auditor reads prose an attacker controls, so it fails in two ways that
only a labelled corpus can measure: it misses a real directive (recall), or it
reports documentation that merely *describes* an attack (precision). Until now
both surfaced by accident — scanning our own plugin skills read ``npx -y`` as a
package named ``-y`` and quoted guidance about "ignore previous instructions"
as coercion.

Each case under ``tests/fixtures/skill_accuracy/<case>/`` holds one instruction
surface plus ``label.json``:

* ``expect`` — categories that MUST fire at ``min_severity`` or above;
* ``must_not`` — categories that must NOT fire above ``max_severity`` (omitted:
  not at any severity). These are zero-tolerance regressions;
* ``packages`` / ``must_not_packages`` — the exact package set extraction must
  produce, and names it must never produce.

Scoring is closed-world for security categories: a finding in a category the
label does not expect is a false positive once it rises above ``low``. Low
findings are evidence-only by design (demoted policy prose, lone keywords) and
do not move a verdict, so they are reported but not scored unless a label names
the category. Metadata hygiene categories are deterministic policy checks, not
detections, and are scored only where a label names them. Registry
verification is network-bound, so it is held fail-open (as on a network error)
and ``unknown_package`` is never scored.

Run:
    python scripts/skill_audit_accuracy.py            # table
    python scripts/skill_audit_accuracy.py --json     # machine-readable
    python scripts/skill_audit_accuracy.py --check    # CI gate vs baseline
    python scripts/skill_audit_accuracy.py --write    # refresh baseline
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

CORPUS = ROOT / "tests" / "fixtures" / "skill_accuracy"
BASELINE = ROOT / "docs" / "SKILL_AUDIT_ACCURACY.json"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

HYGIENE_CATEGORIES = frozenset(
    {
        "missing_source",
        "missing_license",
        "missing_capability_declaration",
        "incomplete_capability_declaration",
        "limited_install",
        "undeclared_dependency",
        "unverifiable_claim",
        "undocumented_network",
    }
)
UNSCORED_CATEGORIES = frozenset({"unknown_package"})
DEFAULT_TOLERANCE = "low"


@dataclass
class Case:
    case_id: str
    kind: str
    surface: Path
    label: dict


@dataclass
class Tally:
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        flagged = self.true_positive + self.false_positive
        return self.true_positive / flagged if flagged else 1.0

    @property
    def recall(self) -> float:
        actual = self.true_positive + self.false_negative
        return self.true_positive / actual if actual else 1.0

    def to_dict(self) -> dict:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
        }


@dataclass
class Outcome:
    cases: int = 0
    benign: int = 0
    risky: int = 0
    categories: dict[str, Tally] = field(default_factory=dict)
    packages: Tally = field(default_factory=Tally)
    version_mismatches: list[str] = field(default_factory=list)
    risky_detected: int = 0
    benign_clean: int = 0
    unscored_low: int = 0
    misses: list[str] = field(default_factory=list)
    spurious: list[str] = field(default_factory=list)
    must_not_violations: list[str] = field(default_factory=list)

    def tally(self, category: str) -> Tally:
        return self.categories.setdefault(category, Tally())

    def overall(self) -> Tally:
        total = Tally()
        for tally in self.categories.values():
            total.true_positive += tally.true_positive
            total.false_positive += tally.false_positive
            total.false_negative += tally.false_negative
        return total

    def to_dict(self) -> dict:
        return {
            "cases": self.cases,
            "benign_cases": self.benign,
            "risky_cases": self.risky,
            "risky_detected": self.risky_detected,
            "benign_clean": self.benign_clean,
            "overall": self.overall().to_dict(),
            "categories": {name: self.categories[name].to_dict() for name in sorted(self.categories)},
            "packages": self.packages.to_dict(),
            "package_version_mismatches": len(self.version_mismatches),
            "must_not_violations": len(self.must_not_violations),
            "unscored_low_findings": self.unscored_low,
        }


def load_cases(root: Path = CORPUS) -> list[Case]:
    cases = []
    for label_path in sorted(root.glob("*/label.json")):
        label = json.loads(label_path.read_text(encoding="utf-8"))
        surface = label_path.parent / label["file"]
        cases.append(Case(case_id=label_path.parent.name, kind=label["kind"], surface=surface, label=label))
    return cases


def _fail_open_verification(packages: list[tuple[str, str]]) -> dict[str, bool]:
    return {name: True for name, _ecosystem in packages}


# Real-shaped credentials are assembled here, not committed, so repository
# secret scanning never sees a live-looking key in the corpus files.
SYNTHETIC_SECRETS = {
    "{{SYNTHETIC_AWS_ACCESS_KEY_ID}}": "AKIA" + "QZ7RTW4XKD2M9VNB",
    "{{SYNTHETIC_AWS_SECRET_ACCESS_KEY}}": "kQ8vX2rLm9" + "Tz4Wb7Nc1Pd6Hf3Jg5Ys0Ua8Ei2RoL",
    "{{SYNTHETIC_GITHUB_TOKEN}}": "ghp_" + "Q7mZ2xK9vT4bN8cW1rP6hF3jG5yS0uA8eI2o",
}


def _materialize(path: Path, workdir: Path) -> Path:
    text = path.read_text(encoding="utf-8")
    if not any(token in text for token in SYNTHETIC_SECRETS):
        return path
    for token, value in SYNTHETIC_SECRETS.items():
        text = text.replace(token, value)
    target = workdir / path.parent.name / path.name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def audit_surface(path: Path) -> tuple[dict[str, str], list[tuple[str, str, str]]]:
    """Return ``{category: highest severity}`` and extracted ``(name, ecosystem, version)``."""
    from agent_bom.parsers import skill_audit
    from agent_bom.parsers.skills import parse_skill_file

    with tempfile.TemporaryDirectory() as workdir:
        scan = parse_skill_file(_materialize(path, Path(workdir)))
        with mock.patch.object(skill_audit, "_batch_verify_packages_sync", _fail_open_verification):
            audit = skill_audit.audit_skill_result(scan)
    fired: dict[str, str] = {}
    for finding in audit.findings:
        current = fired.get(finding.category)
        if current is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[current]:
            fired[finding.category] = finding.severity
    packages = [(pkg.name, pkg.ecosystem, pkg.version) for pkg in scan.packages]
    return fired, packages


def _at_least(severity: str, floor: str) -> bool:
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[floor]


def _score_categories(case: Case, fired: dict[str, str], out: Outcome) -> bool:
    """Score one case's findings; return True when any expectation was met."""
    expected = {item["category"]: item.get("min_severity", "low") for item in case.label.get("expect", [])}
    must_not = {item["category"]: item.get("max_severity") for item in case.label.get("must_not", [])}
    hit_any = False
    for category, floor in expected.items():
        severity = fired.get(category)
        if severity is not None and _at_least(severity, floor):
            out.tally(category).true_positive += 1
            hit_any = True
        else:
            out.tally(category).false_negative += 1
            out.misses.append(f"{case.case_id}: {category} (>= {floor}) got {severity or 'nothing'}")
    for category, severity in fired.items():
        if category in expected:
            continue
        explicit = category in must_not
        if not explicit and category in HYGIENE_CATEGORIES | UNSCORED_CATEGORIES:
            continue
        ceiling = must_not.get(category) if explicit else DEFAULT_TOLERANCE
        if ceiling is not None and SEVERITY_RANK[severity] <= SEVERITY_RANK[ceiling]:
            out.unscored_low += 1
            continue
        out.tally(category).false_positive += 1
        out.spurious.append(f"{case.case_id}: {category} fired at {severity}")
        if explicit:
            out.must_not_violations.append(f"{case.case_id}: {category} fired at {severity} (ceiling {ceiling or 'none'})")
    return hit_any


def _score_packages(case: Case, extracted: list[tuple[str, str, str]], out: Outcome) -> None:
    expected = {(item["name"].lower(), item["ecosystem"]): item.get("version") for item in case.label.get("packages", [])}
    forbidden = {name.lower() for name in case.label.get("must_not_packages", [])}
    seen = set()
    for name, ecosystem, version in extracted:
        key = (name.lower(), ecosystem)
        seen.add(key)
        if key in expected:
            out.packages.true_positive += 1
            want = expected[key]
            if want is not None and want != version:
                out.version_mismatches.append(f"{case.case_id}: {ecosystem}:{name} expected {want} got {version}")
        else:
            out.packages.false_positive += 1
            out.spurious.append(f"{case.case_id}: package {ecosystem}:{name}@{version}")
        if name.lower() in forbidden:
            out.must_not_violations.append(f"{case.case_id}: forbidden package {ecosystem}:{name}")
    for key in expected:
        if key not in seen:
            out.packages.false_negative += 1
            out.misses.append(f"{case.case_id}: package {key[1]}:{key[0]} not extracted")


def score(cases: list[Case]) -> Outcome:
    out = Outcome()
    for case in cases:
        out.cases += 1
        fired, extracted = audit_surface(case.surface)
        spurious_before = len(out.spurious)
        hit_any = _score_categories(case, fired, out)
        _score_packages(case, extracted, out)
        if case.kind == "benign":
            out.benign += 1
            out.benign_clean += len(out.spurious) == spurious_before
        else:
            out.risky += 1
            out.risky_detected += hit_any
    return out


def render_table(result: Outcome) -> str:
    payload = result.to_dict()
    rows = [f"cases: {payload['cases']}  (benign {payload['benign_cases']}, risky {payload['risky_cases']})"]
    rows.append(f"  risky files detected: {payload['risky_detected']}/{payload['risky_cases']}")
    rows.append(f"  benign files clean:   {payload['benign_clean']}/{payload['benign_cases']}")
    rows.append("")
    rows.append(f"  {'category':<36} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}")
    for name, tally in payload["categories"].items():
        rows.append(
            f"  {name:<36} {tally['true_positive']:>4} {tally['false_positive']:>4} {tally['false_negative']:>4}"
            f" {tally['precision']:>10.4f} {tally['recall']:>8.4f}"
        )
    for name in ("overall", "packages"):
        tally = payload[name]
        rows.append(
            f"  {name.upper():<36} {tally['true_positive']:>4} {tally['false_positive']:>4} {tally['false_negative']:>4}"
            f" {tally['precision']:>10.4f} {tally['recall']:>8.4f}"
        )
    rows.append(f"  must_not violations: {payload['must_not_violations']}  version mismatches: {payload['package_version_mismatches']}")
    rows.extend(f"    MISSED: {line}" for line in result.misses)
    rows.extend(f"    SPURIOUS: {line}" for line in result.spurious)
    rows.extend(f"    MUST-NOT: {line}" for line in result.must_not_violations)
    rows.extend(f"    VERSION: {line}" for line in result.version_mismatches)
    return "\n".join(rows)


def regressions(payload: dict, prior: dict) -> list[str]:
    """Every way the current payload is worse than the recorded baseline."""
    errors = []
    for name in ("overall", "packages"):
        for metric in ("precision", "recall"):
            if payload[name][metric] + 1e-9 < prior[name][metric]:
                errors.append(f"{name} {metric} regressed {prior[name][metric]:.4f} -> {payload[name][metric]:.4f}")
    for category, before in prior["categories"].items():
        now = payload["categories"].get(category)
        if now is None:
            errors.append(f"category {category} no longer scored; corpus coverage shrank")
            continue
        for metric in ("precision", "recall"):
            if now[metric] + 1e-9 < before[metric]:
                errors.append(f"{category} {metric} regressed {before[metric]:.4f} -> {now[metric]:.4f}")
        if now["false_positive"] > before["false_positive"]:
            errors.append(f"{category} false positives grew {before['false_positive']} -> {now['false_positive']}")
    for count in ("cases", "benign_cases", "risky_cases"):
        if payload[count] < prior[count]:
            errors.append(f"{count} dropped {prior[count]} -> {payload[count]}; coverage must not shrink silently")
    if payload["must_not_violations"] > prior["must_not_violations"]:
        errors.append(f"must_not violations grew {prior['must_not_violations']} -> {payload['must_not_violations']}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail when accuracy regresses below the recorded baseline")
    parser.add_argument("--write", action="store_true", help="record current results as the baseline")
    parser.add_argument("--json", action="store_true", help="print the JSON payload instead of the table")
    args = parser.parse_args()

    result = score(load_cases())
    payload = result.to_dict()
    print(json.dumps(payload, indent=2) if args.json else render_table(result))

    if args.write:
        BASELINE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote baseline {BASELINE.relative_to(ROOT)}", file=sys.stderr)
        return 0
    if args.check:
        if not BASELINE.exists():
            print(f"ERROR: no baseline at {BASELINE.relative_to(ROOT)}; run --write", file=sys.stderr)
            return 1
        errors = regressions(payload, json.loads(BASELINE.read_text(encoding="utf-8")))
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1 if errors else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
