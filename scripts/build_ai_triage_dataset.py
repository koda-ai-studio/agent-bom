#!/usr/bin/env python3
"""Build the labelled AI-triage evaluation dataset from this repository's own evidence.

Every finding comes out of the real conversion code, and most out of a real scan of
a committed fixture. Every label states its basis. Nothing here is account data:
inputs are public advisories, the public CISA KEV catalogue, and synthetic fixtures.

The split is decided by a hash of the case id before any model has run, so a change
of prompt cannot move a hard case out of the held-out set.

Run:
    python scripts/build_ai_triage_dataset.py          # write
    python scripts/build_ai_triage_dataset.py --check  # fail when the committed file differs
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from ai_triage_dataset_cases import (  # noqa: E402
    ADVERSARIAL_CASES,
    FRESH_ADVERSARIAL_CASES,
    IAC_LOOKALIKES,
    KEV_CASES,
    KEV_CATALOG_VERSION,
    MALICIOUS_CASES,
)

from agent_bom.finding import (  # noqa: E402
    Asset,
    Finding,
    FindingSource,
    FindingType,
    blast_radius_to_finding,
    cloud_cis_check_to_finding,
    iac_finding_to_finding,
    malicious_package_to_finding,
)
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability  # noqa: E402

DATASET_VERSION = "ai-triage-dataset.v1"
OUTPUT = ROOT / "tests" / "fixtures" / "ai_triage_eval" / "dataset.v1.json"
HELD_OUT_PERCENT = 40
_SEVERITIES = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
_FINDING_KEYS = (
    "id",
    "finding_type",
    "source",
    "severity",
    "severity_source",
    "title",
    "description",
    "cve_id",
    "cwe_ids",
    "cvss_score",
    "epss_score",
    "is_kev",
    "is_malicious",
    "fixed_version",
    "risk_score",
    "reachability",
    "graph_reachable",
    "provider",
    "environment",
    "account_ref",
    "region",
    "affected_agents",
    "affected_servers",
    "exposed_credentials",
    "exposed_tools",
)
_EVIDENCE_KEYS = (
    "package_name",
    "package_version",
    "ecosystem",
    "package_is_direct",
    "package_parent",
    "package_dependency_depth",
    "package_dependency_scope",
    "match_confidence_tier",
    "file_path",
    "line_number",
    "rule_id",
    "symbol_reachability",
    "iac",
)


@dataclass
class Case:
    case_id: str
    category: str
    label: str
    basis: str
    source: str
    finding: Finding
    adversarial: dict[str, Any] = field(default_factory=dict)


def _serialize(finding: Finding) -> dict[str, Any]:
    payload = finding.to_dict()
    row = {key: payload.get(key) for key in _FINDING_KEYS}
    row["asset"] = {key: payload["asset"].get(key) for key in ("name", "asset_type", "identifier", "location", "provider", "environment")}
    row["evidence"] = {key: finding.evidence[key] for key in _EVIDENCE_KEYS if finding.evidence.get(key) is not None}
    return row


def _vulnerable_finding(
    *,
    advisory: str,
    summary: str,
    severity: str,
    package: str,
    version: str,
    ecosystem: str,
    fixed: str | None,
    is_kev: bool = False,
    epss: float | None = None,
    cvss: float | None = None,
    **reach: Any,
) -> Finding:
    vulnerability = Vulnerability(
        id=advisory,
        summary=summary,
        severity=Severity(severity),
        fixed_version=fixed,
        is_kev=is_kev,
        epss_score=epss,
        cvss_score=cvss,
    )
    pkg = Package(name=package, version=version, ecosystem=ecosystem, is_direct=reach.pop("direct", True))
    radius = BlastRadius(
        vulnerability=vulnerability, package=pkg, affected_servers=[], affected_agents=[], exposed_credentials=[], exposed_tools=[]
    )
    for key, value in reach.items():
        setattr(radius, key, value)
    finding = blast_radius_to_finding(radius)
    finding.fixed_version = fixed
    return finding


def _single_window_advisories() -> list[dict[str, Any]]:
    corpus = json.loads((ROOT / "tests" / "fixtures" / "cve_accuracy_corpus.json").read_text())
    facts = json.loads((OUTPUT.parent / "osv_advisory_facts.json").read_text())["advisories"]
    usable: list[dict[str, Any]] = []
    for entry in corpus["entries"]:
        advisory = entry["advisory"]
        affected = [a for a in advisory.get("affected", []) if a.get("versions") and a.get("ranges")]
        if len(affected) != 1 or len(affected[0]["ranges"]) != 1:
            continue
        events = affected[0]["ranges"][0].get("events", [])
        introduced = [e["introduced"] for e in events if "introduced" in e]
        fixed = [e["fixed"] for e in events if "fixed" in e]
        versions = affected[0]["versions"]
        if len(introduced) != 1 or len(fixed) != 1 or not versions or fixed[0] in versions:
            continue
        fact = facts.get(advisory["id"])
        severity = _SEVERITIES.get(str((fact or {}).get("severity", "")).upper())
        if severity is None:
            continue
        advisory = {**advisory, "summary": fact["summary"]}
        usable.append({"advisory": advisory, "affected": affected[0], "introduced": introduced[0], "fixed": fixed[0], "severity": severity})
    return sorted(usable, key=lambda item: hashlib.sha256(item["advisory"]["id"].encode()).hexdigest())


def _summary(advisory: dict[str, Any]) -> str:
    return str(advisory.get("summary") or advisory.get("details") or advisory["id"])[:300]


def _advisory_cases(rows: list[dict[str, Any]]) -> list[Case]:
    cases: list[Case] = []
    source = "tests/fixtures/cve_accuracy_corpus.json (OSV)"

    def finding(row: dict[str, Any], version: str, **extra: Any) -> Finding:
        advisory = row["advisory"]
        package = row["affected"]["package"]
        return _vulnerable_finding(
            advisory=advisory["id"],
            summary=_summary(advisory),
            severity=extra.pop("severity", row["severity"]),
            package=package["name"],
            version=version,
            ecosystem=package["ecosystem"],
            fixed=row["fixed"],
            **extra,
        )

    cursor = iter(rows)
    for index in range(26):
        row = next(cursor)
        version = row["affected"]["versions"][-1]
        cases.append(
            Case(
                f"vuln-tp-{index:02d}",
                "vulnerable_version",
                "true_positive",
                f"{version} is listed in the advisory's versions[].",
                source,
                finding(row, version),
            )
        )
    for index in range(26):
        row = next(cursor)
        cases.append(
            Case(
                f"vuln-fp-fixed-{index:02d}",
                "version_at_fix",
                "false_positive",
                f"{row['fixed']} is the advisory's fix event and is absent from versions[]; "
                "matching it is the stale-range false positive this repo's matcher gate guards against.",
                source,
                finding(row, row["fixed"]),
            )
        )
    below = 0
    for row in cursor:
        introduced = row["introduced"]
        if introduced in {"0", "0.0.0"} or introduced in row["affected"]["versions"][:0]:
            continue
        pre_release = _release_before(introduced)
        if pre_release is None or pre_release in row["affected"]["versions"]:
            continue
        cases.append(
            Case(
                f"vuln-fp-below-{below:02d}",
                "version_before_introduced",
                "false_positive",
                f"{pre_release} precedes the advisory's introduced event {introduced}. "
                "The fixed version alone cannot show this, which makes it a hard case by design.",
                source,
                finding(row, pre_release),
            )
        )
        below += 1
        if below == 6:
            break
    return cases


def _release_before(version: str) -> str | None:
    parts = version.split(".")
    if not all(part.isdigit() for part in parts) or len(parts) < 2:
        return None
    if int(parts[0]) >= 1:
        return ".".join(str(item) for item in [int(parts[0]) - 1, *([0] * (len(parts) - 1))])
    return None


def _reachability_cases(rows: list[dict[str, Any]]) -> list[Case]:
    cases: list[Case] = []
    source = "tests/fixtures/cve_accuracy_corpus.json (OSV) with BlastRadius reachability evidence"
    criticals = [row for row in rows if row["severity"] in {"critical", "high"}][-20:]
    for index, row in enumerate(criticals[:10]):
        advisory, package = row["advisory"], row["affected"]["package"]
        version = row["affected"]["versions"][0]
        finding = _vulnerable_finding(
            advisory=advisory["id"],
            summary=_summary(advisory),
            severity="critical",
            package=package["name"],
            version=version,
            ecosystem=package["ecosystem"],
            fixed=row["fixed"],
            graph_reachable=True,
            graph_min_hop_distance=2,
            symbol_reachability="reachable",
            cvss=9.8,
        )
        cases.append(
            Case(
                f"reach-critical-{index:02d}",
                "reachable_critical",
                "true_positive",
                f"{version} is in versions[], and the fixture records a graph path plus a reachable vulnerable symbol.",
                source,
                finding,
            )
        )
    for index, row in enumerate(criticals[10:20]):
        advisory, package = row["advisory"], row["affected"]["package"]
        version = row["affected"]["versions"][0]
        finding = _vulnerable_finding(
            advisory=advisory["id"],
            summary=_summary(advisory),
            severity=row["severity"],
            package=package["name"],
            version=version,
            ecosystem=package["ecosystem"],
            fixed=row["fixed"],
            graph_reachable=False,
            symbol_reachability="not_reachable",
            direct=False,
        )
        cases.append(
            Case(
                f"unreachable-{index:02d}",
                "unreachable",
                "true_positive",
                f"{version} is in versions[], so the claim is correct. Reachability lowers priority; it does not make the advisory false.",
                source,
                finding,
            )
        )
    return cases


def _kev_cases() -> list[Case]:
    cases: list[Case] = []
    for index, item in enumerate(KEV_CASES):
        finding = _vulnerable_finding(
            advisory=item["cve"],
            summary=item["summary"],
            severity=item["severity"],
            package=item["package"],
            version=item["version"],
            ecosystem=item["ecosystem"],
            fixed=item["fixed"],
            is_kev=True,
            epss=item.get("epss"),
        )
        finding.is_kev = True
        cases.append(
            Case(
                f"kev-{index:02d}",
                "kev",
                item["label"],
                f"{item['cve']} is in the CISA KEV catalogue {KEV_CATALOG_VERSION}; {item['basis']}",
                "CISA KEV catalogue + public advisory",
                finding,
            )
        )
    return cases


def _malicious_cases() -> list[Case]:
    cases: list[Case] = []
    for index, item in enumerate(MALICIOUS_CASES):
        package = Package(name=item["name"], version=item["version"], ecosystem=item["ecosystem"])
        package.is_malicious = True
        package.malicious_reason = item["reason"]
        finding = malicious_package_to_finding(package, affected_agents=[], affected_servers=[])
        cases.append(Case(f"malicious-{index:02d}", "malicious_package", item["label"], item["basis"], item["source"], finding))
    return cases


def _iac_cases() -> list[Case]:
    from agent_bom.iac import scan_iac_with_context

    with tempfile.TemporaryDirectory() as scratch:
        target = Path(scratch) / "iac_accuracy"
        shutil.copytree(ROOT / "tests" / "fixtures" / "iac_accuracy", target)
        findings = scan_iac_with_context(target).findings
        rows = []
        for item in sorted(findings, key=lambda f: (f.file_path, f.line_number, f.rule_id)):
            data = item.to_dict() if hasattr(item, "to_dict") else dict(vars(item))
            data["file_path"] = str(data["file_path"]).replace(str(target) + "/", "")
            rows.append(data)
    cases: list[Case] = []
    by_rule: dict[str, dict[str, Any]] = {}
    for data in rows:
        by_rule.setdefault(str(data["rule_id"]), data)
    source = "real scan of tests/fixtures/iac_accuracy"
    for index, data in enumerate(rows[:: max(len(rows) // 14, 1)][:14]):
        cases.append(
            Case(
                f"iac-tp-{index:02d}",
                "cloud_misconfiguration",
                "true_positive",
                f"tests/test_iac_accuracy_fixture.py pins this planted issue at {data['file_path']}:{data['line_number']}.",
                source,
                iac_finding_to_finding(data),
            )
        )
    for index, item in enumerate(IAC_LOOKALIKES):
        template = by_rule.get(item["rule_id"]) or next(iter(by_rule.values()))
        data = {**template, **item["override"], "rule_id": item["rule_id"]}
        cases.append(
            Case(
                f"iac-fp-{index:02d}",
                "cloud_misconfiguration_lookalike",
                "false_positive",
                item["basis"],
                "rule output re-targeted at a look-alike the IaC accuracy tests pin as quiet",
                iac_finding_to_finding(data),
            )
        )
    return cases


def _cis_cases() -> list[Case]:
    cases: list[Case] = []
    source = "tests/fixtures/cis_characterization"
    seen = 0
    for provider in ("aws", "azure", "gcp"):
        data = json.loads((ROOT / "tests" / "fixtures" / "cis_characterization" / f"{provider}.json").read_text())
        checks = _collect_checks(data)
        failing = [check for check in checks if check.get("status") == "fail" and check.get("severity")][:3]
        for check in failing:
            finding = cloud_cis_check_to_finding(check, provider)
            cases.append(
                Case(
                    f"cis-tp-{seen:02d}",
                    "cloud_misconfiguration",
                    "true_positive",
                    f"The recorded {provider} API response in this characterization fixture fails CIS control {check.get('check_id')}.",
                    source,
                    finding,
                )
            )
            seen += 1
    return cases


def _collect_checks(node: Any) -> list[dict[str, Any]]:
    if isinstance(node, dict):
        if "check_id" in node and "status" in node:
            return [node]
        return [check for value in node.values() for check in _collect_checks(value)]
    if isinstance(node, list):
        return [check for value in node for check in _collect_checks(value)]
    return []


def _skill_cases() -> list[Case]:
    from skill_audit_accuracy import _CorpusPath, _fail_open_verification

    from agent_bom.parsers import skill_audit
    from agent_bom.parsers.skills import parse_skill_file

    cases: list[Case] = []
    corpus = ROOT / "tests" / "fixtures" / "skill_accuracy"
    benign = risky = 0
    for directory in sorted(corpus.iterdir()):
        label = json.loads((directory / "label.json").read_text())
        scan = parse_skill_file(_CorpusPath(directory / label["file"]))
        with mock.patch.object(skill_audit, "_batch_verify_packages_sync", _fail_open_verification):
            audit = skill_audit.audit_skill_result(scan)
        security = [
            f for f in audit.findings if f.category not in {"missing_source", "missing_license", "missing_metadata", "unknown_package"}
        ]
        expected = {item["category"] for item in label.get("expect", [])}
        for finding in security:
            detail = finding.detail.replace(str(ROOT) + "/", "")
            row = Finding(
                finding_type=FindingType.SKILL_RISK,
                source=FindingSource.SKILL,
                asset=Asset(
                    name=f"{directory.name}/{label['file']}",
                    asset_type="skill_file",
                    location=f"tests/fixtures/skill_accuracy/{directory.name}/{label['file']}",
                ),
                severity=finding.severity,
                title=finding.title,
                description=detail,
                evidence={"rule_id": finding.category, "file_path": f"tests/fixtures/skill_accuracy/{directory.name}/{label['file']}"},
            )
            if label["kind"] == "benign" and benign < 14:
                cases.append(
                    Case(
                        f"skill-fp-{benign:02d}",
                        "skill_documentation_lookalike",
                        "false_positive",
                        f"Corpus label kind=benign: {label.get('description', '')}",
                        f"real audit of tests/fixtures/skill_accuracy/{directory.name}",
                        row,
                    )
                )
                benign += 1
            elif label["kind"] == "risky" and finding.category in expected and risky < 14:
                cases.append(
                    Case(
                        f"skill-tp-{risky:02d}",
                        "skill_risk",
                        "true_positive",
                        f"Corpus label kind=risky expects category {finding.category}: {label.get('description', '')}",
                        f"real audit of tests/fixtures/skill_accuracy/{directory.name}",
                        row,
                    )
                )
                risky += 1
                break
    return cases


def _adversarial_cases(base: list[Case], items: list[dict[str, str]], prefix: str) -> list[Case]:
    """Hostile copies of real cases; the truth of the underlying claim does not change."""
    by_id = {case.case_id: case for case in base}
    cases: list[Case] = []
    for index, item in enumerate(items):
        origin = by_id[item["base"]]
        data = _serialize(origin.finding)
        hostile = item["text"]
        where = item["field"]
        if where == "title":
            data["title"] = f"{hostile} {data['title']}"
        elif where == "description":
            data["description"] = f"{data['description']} {hostile}"
        elif where == "asset":
            data["asset"]["name"] = hostile
        elif where == "package":
            data["evidence"]["package_name"] = hostile
            data["asset"]["name"] = hostile
        from agent_bom.domain.finding_rehydrate import finding_from_dict

        finding = finding_from_dict(data)
        assert finding is not None
        finding.id = f"{prefix}-{index:02d}-{origin.finding.id}"[:128]
        cases.append(
            Case(
                f"{prefix}-{index:02d}",
                "adversarial",
                origin.label,
                f"Same truth as {origin.case_id}: {origin.basis}",
                f"{origin.source}, with attacker-written text in the {where} field",
                finding,
                adversarial={"goal": item["goal"], "field": where, "marker": item.get("marker", "")},
            )
        )
    return cases


def _split(case_id: str) -> str:
    if case_id.startswith("advx-"):
        return "heldout"
    bucket = int(hashlib.sha256(f"{DATASET_VERSION}:{case_id}".encode()).hexdigest(), 16) % 100
    return "heldout" if bucket < HELD_OUT_PERCENT else "dev"


def build() -> dict[str, Any]:
    random.seed(0)
    rows = _single_window_advisories()
    base = [
        *_advisory_cases(rows[:-20]),
        *_reachability_cases(rows),
        *_kev_cases(),
        *_malicious_cases(),
        *_iac_cases(),
        *_cis_cases(),
        *_skill_cases(),
    ]
    cases = [*base, *_adversarial_cases(base, ADVERSARIAL_CASES, "adv"), *_adversarial_cases(base, FRESH_ADVERSARIAL_CASES, "advx")]
    identifiers = [case.finding.id for case in cases]
    if len(set(identifiers)) != len(identifiers):
        seen: set[str] = set()
        for case in cases:
            if case.finding.id in seen:
                case.finding.id = f"{case.finding.id}-{case.case_id}"[:128]
            seen.add(case.finding.id)
    payload = {
        "version": DATASET_VERSION,
        "description": "Labelled findings for scoring advisory AI triage. Public and synthetic data only.",
        "label_definitions": {
            "true_positive": "The scanner's claim is correct, whatever its priority.",
            "false_positive": "The scanner's claim is wrong on the recorded evidence.",
        },
        "kev_catalog_version": KEV_CATALOG_VERSION,
        "cases": [
            {
                "case_id": case.case_id,
                "split": _split(case.case_id),
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
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(build(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            print(f"{OUTPUT} is stale; run scripts/build_ai_triage_dataset.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered)
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
