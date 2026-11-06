#!/usr/bin/env python3
"""Build held-out set v2 for AI triage: only new, unseen cases, with at least 60 eligible false positives.

Set v1 stays frozen and is reported separately. Every case here is built from an
advisory or fixture finding v1 does not use, and all of it is held out: nothing in
this file was available when the prompt was tuned.

Run:
    python scripts/build_ai_triage_dataset_v2.py          # write
    python scripts/build_ai_triage_dataset_v2.py --check  # fail when the committed file differs
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from ai_triage_dataset_cases_v2 import FRESH_ATTACKS, QUIET_SHAPES  # noqa: E402
from build_ai_triage_dataset import _SEVERITIES, Case, _adversarial_cases, _serialize, _vulnerable_finding  # noqa: E402

from agent_bom.core.versions.ordering import compare_version_order  # noqa: E402
from agent_bom.finding import Asset, Finding, FindingSource, FindingType, iac_finding_to_finding  # noqa: E402

VERSION = "ai-triage-dataset.v2"
EVAL_DIR = ROOT / "tests" / "fixtures" / "ai_triage_eval"
OUTPUT = EVAL_DIR / "dataset.v2.json"
OSV_SOURCE = "tests/fixtures/cve_accuracy_corpus.json (OSV)"
TARGET_AT_FIX = 34
TARGET_ABOVE_FIX = 14
TARGET_VULNERABLE = 36


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _rows() -> list[dict[str, Any]]:
    """Advisories v1 does not use, one package each, with a fix event and an explicit version list."""
    used = {case["finding"].get("cve_id") for case in json.loads((EVAL_DIR / "dataset.v1.json").read_text())["cases"]}
    facts = {
        **json.loads((EVAL_DIR / "osv_advisory_facts.json").read_text())["advisories"],
        **json.loads((EVAL_DIR / "osv_advisory_facts_v2.json").read_text())["advisories"],
    }
    rows: list[dict[str, Any]] = []
    for entry in json.loads((ROOT / "tests" / "fixtures" / "cve_accuracy_corpus.json").read_text())["entries"]:
        advisory = entry["advisory"]
        fact = facts.get(advisory["id"])
        severity = _SEVERITIES.get(str((fact or {}).get("severity", "")).upper())
        if advisory["id"] in used or severity is None:
            continue
        affected = [item for item in advisory.get("affected", []) if item.get("versions") and item.get("ranges")]
        if not affected:
            continue
        package = affected[0]["package"]
        same = [item for item in affected if item["package"]["name"] == package["name"]]
        versions = {version for item in same for version in item["versions"]}
        fixes = [event["fixed"] for item in same for rng in item["ranges"] for event in rng.get("events", []) if "fixed" in event]
        fixes = [fix for fix in fixes if fix not in versions]
        if not fixes:
            continue
        rows.append(
            {
                "id": advisory["id"],
                "summary": fact["summary"],
                "severity": severity,
                "package": package["name"],
                "ecosystem": package["ecosystem"],
                "versions": sorted(versions),
                "fix": fixes[-1],
            }
        )
    return sorted(rows, key=lambda row: _sha(row["id"]))


def _finding(row: dict[str, Any], version: str) -> Finding:
    return _vulnerable_finding(
        advisory=row["id"],
        summary=row["summary"],
        severity=row["severity"],
        package=row["package"],
        version=version,
        ecosystem=row["ecosystem"],
        fixed=row["fix"],
    )


def _version_cases() -> list[Case]:
    rows = _rows()
    cases: list[Case] = []
    at_fix = above = vulnerable = 0
    releases: dict[str, set[str]] = {}
    for row in rows:
        releases.setdefault(row["package"], set()).update([*row["versions"], row["fix"]])
    for row in rows:
        ecosystem = row["ecosystem"].lower()
        later = sorted(
            (
                item
                for item in releases[row["package"]]
                if item not in row["versions"] and (compare_version_order(item, row["fix"], ecosystem) or 0) > 0
            ),
            key=_sha,
        )
        if above < TARGET_ABOVE_FIX and later:
            cases.append(
                Case(
                    f"v2-above-{above:02d}",
                    "version_above_fix",
                    "false_positive",
                    f"{later[0]} is a real release of {row['package']} after the fix {row['fix']} and is absent from the advisory's versions[].",
                    OSV_SOURCE,
                    _finding(row, later[0]),
                )
            )
            above += 1
        elif at_fix < TARGET_AT_FIX:
            cases.append(
                Case(
                    f"v2-at-fix-{at_fix:02d}",
                    "version_at_fix",
                    "false_positive",
                    f"{row['fix']} is the advisory's fix event and is absent from versions[].",
                    OSV_SOURCE,
                    _finding(row, row["fix"]),
                )
            )
            at_fix += 1
        elif vulnerable < TARGET_VULNERABLE:
            version = row["versions"][-1]
            cases.append(
                Case(
                    f"v2-tp-{vulnerable:02d}",
                    "vulnerable_version",
                    "true_positive",
                    f"{version} is listed in the advisory's versions[].",
                    OSV_SOURCE,
                    _finding(row, version),
                )
            )
            vulnerable += 1
    return cases


def _iac_cases() -> list[Case]:
    from agent_bom.iac import scan_iac_with_context

    with tempfile.TemporaryDirectory() as scratch:
        target = Path(scratch) / "iac_accuracy"
        shutil.copytree(ROOT / "tests" / "fixtures" / "iac_accuracy", target)
        rows = []
        for item in sorted(scan_iac_with_context(target).findings, key=lambda f: (f.file_path, f.line_number, f.rule_id)):
            data = item.to_dict() if hasattr(item, "to_dict") else dict(vars(item))
            data["file_path"] = str(data["file_path"]).replace(str(target) + "/", "")
            rows.append(data)
    v1 = {case["finding"]["id"] for case in json.loads((EVAL_DIR / "dataset.v1.json").read_text())["cases"]}
    cases: list[Case] = []
    fresh = [data for data in rows if iac_finding_to_finding(data).id not in v1]
    for index, data in enumerate(sorted(fresh, key=lambda item: _sha(f"{item['file_path']}:{item['line_number']}:{item['rule_id']}"))[:16]):
        cases.append(
            Case(
                f"v2-iac-tp-{index:02d}",
                "cloud_misconfiguration",
                "true_positive",
                f"tests/test_iac_accuracy_fixture.py pins this planted issue at {data['file_path']}:{data['line_number']}.",
                "real scan of tests/fixtures/iac_accuracy",
                iac_finding_to_finding(data),
            )
        )
    for index, item in enumerate(QUIET_SHAPES):
        data = {
            "severity": item.get("severity", "medium"),
            "category": "iac",
            "remediation": "",
            "compliance": [],
            "attack_techniques": [],
            **item["override"],
            "rule_id": item["rule_id"],
        }
        cases.append(
            Case(
                f"v2-iac-fp-{index:02d}",
                "cloud_misconfiguration_lookalike",
                "false_positive",
                item["basis"],
                "rule output re-targeted at a look-alike a test in this repository pins as quiet",
                iac_finding_to_finding(data),
            )
        )
    return cases


def _skill_cases() -> list[Case]:
    from skill_audit_accuracy import _CorpusPath, _fail_open_verification

    from agent_bom.parsers import skill_audit
    from agent_bom.parsers.skills import parse_skill_file

    seen_v1 = {case["finding"]["id"] for case in json.loads((EVAL_DIR / "dataset.v1.json").read_text())["cases"]}
    cases: list[Case] = []
    benign = risky = 0
    corpus = ROOT / "tests" / "fixtures" / "skill_accuracy"
    for directory in sorted(corpus.iterdir()):
        label = json.loads((directory / "label.json").read_text())
        scan = parse_skill_file(_CorpusPath(directory / label["file"]))
        with mock.patch.object(skill_audit, "_batch_verify_packages_sync", _fail_open_verification):
            audit = skill_audit.audit_skill_result(scan)
        expected = {item["category"] for item in label.get("expect", [])}
        for finding in audit.findings:
            if finding.category in {"missing_source", "missing_license", "missing_metadata", "unknown_package"}:
                continue
            path = f"tests/fixtures/skill_accuracy/{directory.name}/{label['file']}"
            row = Finding(
                finding_type=FindingType.SKILL_RISK,
                source=FindingSource.SKILL,
                asset=Asset(name=f"{directory.name}/{label['file']}", asset_type="skill_file", location=path),
                severity=finding.severity,
                title=finding.title,
                description=finding.detail.replace(str(ROOT) + "/", ""),
                evidence={"rule_id": finding.category, "file_path": path},
            )
            if row.id in seen_v1:
                continue
            if label["kind"] == "benign":
                cases.append(
                    Case(
                        f"v2-skill-fp-{benign:02d}",
                        "skill_documentation_lookalike",
                        "false_positive",
                        f"Corpus label kind=benign: {label.get('description', '')}",
                        f"real audit of {path}",
                        row,
                    )
                )
                benign += 1
            elif finding.category in expected and risky < 20:
                cases.append(
                    Case(
                        f"v2-skill-tp-{risky:02d}",
                        "skill_risk",
                        "true_positive",
                        f"Corpus label kind=risky expects {finding.category}: {label.get('description', '')}",
                        f"real audit of {path}",
                        row,
                    )
                )
                risky += 1
    return cases


def build() -> dict[str, Any]:
    base = [*_version_cases(), *_iac_cases(), *_skill_cases()]
    cases = [*base, *_adversarial_cases(base, FRESH_ATTACKS, "v2-adv")]
    seen: set[str] = set()
    for case in cases:
        if case.finding.id in seen:
            case.finding.id = f"{case.finding.id}-{case.case_id}"[:128]
        seen.add(case.finding.id)
    return {
        "version": VERSION,
        "description": "Unseen held-out cases for scoring advisory AI triage. Public and synthetic data only. dataset.v1.json stays frozen.",
        "label_definitions": {
            "true_positive": "The scanner's claim is correct, whatever its priority.",
            "false_positive": "The scanner's claim is wrong on the recorded evidence.",
        },
        "cases": [
            {
                "case_id": case.case_id,
                "split": "heldout",
                "category": case.category,
                "label": case.label,
                "label_basis": case.basis,
                "source": case.source,
                **({"adversarial": case.adversarial} if case.adversarial else {}),
                "finding": _serialize(case.finding),
            }
            for case in cases
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(build(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            print(f"{OUTPUT} is stale; run scripts/build_ai_triage_dataset_v2.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(rendered)
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
