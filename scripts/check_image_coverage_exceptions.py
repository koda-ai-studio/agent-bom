#!/usr/bin/env python3
"""Accept a ``partial`` image scan only for reviewed, exact coverage exceptions.

An image gate fails closed when the scan is ``partial``. Some images ship a
runtime that no advisory source agent-bom consults tracks (the UI image's
Node.js binary), so their scan is honestly partial on every run. This check
runs only after the scanner exited ``1`` and passes only when every reason for
that exit is a coverage gap listed under ``coverage_exceptions`` in
``docs/security/image-exceptions.yaml`` for this image, at the exact runtime
version, and not expired. It is stricter than the scanner's own gates: any
other coverage issue, an incomplete scope, a malicious package or an active
finding at the gate severity still fails, so it can never pass a scan the
scanner failed for another reason.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
FAIL_CLOSED_SEVERITIES = frozenset({"unknown", "none", ""})
# CVE rows are gated through ``blast_radius``, which already reflects
# ``--exclude-unfixable`` and ignore files; errored controls are missing
# evidence, not findings (same exclusions as the scanner's own gate).
NON_GATING_FINDING_TYPES = frozenset({"CVE", "CIS_ERROR", "CLOUD_BEST_PRACTICE_ERROR"})


def _blocks(severity: object, threshold: int) -> bool:
    label = str(severity or "").strip().lower()
    return label in FAIL_CLOSED_SEVERITIES or SEVERITY_RANK.get(label, 0) >= threshold


def _accepted_gaps(registry: Path, image: str, today: date) -> tuple[dict[tuple[str, str], str], list[str]]:
    """``{(reason, release): exception id}`` in force for ``image``, plus expiry notes."""
    data = yaml.safe_load(registry.read_text(encoding="utf-8")) or {}
    accepted: dict[tuple[str, str], str] = {}
    expired: list[str] = []
    for entry in data.get("coverage_exceptions") or []:
        if not isinstance(entry, dict) or image not in (entry.get("images") or []):
            continue
        key = (str(entry.get("reason_code") or ""), str(entry.get("release") or ""))
        expires = date.fromisoformat(str(entry.get("expires_at")))
        if expires < today:
            expired.append(f"coverage exception {entry.get('id')} for {key[1]} expired on {expires.isoformat()}; review and renew it")
            continue
        accepted[key] = str(entry.get("id"))
    return accepted, expired


def _coverage_failures(report: dict[str, Any], accepted: dict[tuple[str, str], str]) -> list[str]:
    run = report.get("scan_run")
    if not isinstance(run, dict):
        return ["report has no scan_run; cannot establish why the scan was not complete"]
    outcome = str(run.get("outcome") or "")
    if outcome != "partial":
        return [f"scan outcome is {outcome or 'missing'}; only a partial scan can be accepted, so the scanner failed for another reason"]
    gaps = {
        (str(w.get("reason") or ""), str(w.get("release") or "")): str(w.get("detail") or "")
        for w in report.get("coverage_warnings") or []
        if isinstance(w, dict)
    }
    allowed_messages: set[str] = set()
    for (reason, release), detail in gaps.items():
        if (reason, release) in accepted:
            allowed_messages.update({detail, f"{release}: {detail}"})
    failures = [
        f"coverage scope {scope.get('name')} is {scope.get('status')}"
        for scope in run.get("scopes") or []
        if isinstance(scope, dict) and scope.get("requested", True) and scope.get("status") not in {"complete", "skipped"}
    ]
    for issue in run.get("issues") or []:
        if not isinstance(issue, dict) or issue.get("affects_coverage") is False:
            continue
        message = str(issue.get("message") or "")
        if message not in allowed_messages:
            failures.append(f"unaccepted coverage issue ({issue.get('code')}): {message}")
    return failures


def _finding_failures(report: dict[str, Any], threshold: int) -> list[str]:
    failures: list[str] = []
    for row in report.get("blast_radius") or []:
        if isinstance(row, dict) and row.get("suppressed") is not True and _blocks(row.get("severity"), threshold):
            failures.append(f"active {row.get('severity')} vulnerability {row.get('vulnerability_id')}")
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict) or finding.get("suppressed") is True:
            continue
        kind = str(finding.get("finding_type") or "")
        if finding.get("is_malicious") is True:
            failures.append(f"malicious finding {finding.get('id')} ({kind})")
        elif kind not in NON_GATING_FINDING_TYPES and _blocks(finding.get("effective_severity") or finding.get("severity"), threshold):
            failures.append(f"active {finding.get('severity')} {kind} finding {finding.get('id')}")
    for package in report.get("packages") or []:
        if isinstance(package, dict) and package.get("is_malicious") is True:
            failures.append(f"malicious package {package.get('name')}@{package.get('version')}")
    return failures


def gate_failures(report_path: Path, registry: Path, *, image: str, today: date, fail_on_severity: str) -> list[str]:
    """Reasons the scan cannot be accepted; empty means only reviewed coverage gaps remain."""
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"cannot read scan report {report_path}: {exc}"]
    if not isinstance(report, dict):
        return ["scan report is not a JSON object"]
    accepted, expired = _accepted_gaps(registry, image, today)
    failures = _coverage_failures(report, accepted)
    if failures:
        failures.extend(expired)
    return failures + _finding_failures(report, SEVERITY_RANK[fail_on_severity])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=Path, required=True, help="agent-bom JSON report of the image scan")
    parser.add_argument("--exceptions", type=Path, required=True, help="docs/security/image-exceptions.yaml")
    parser.add_argument("--image", required=True, help="published image name the exceptions are scoped to")
    parser.add_argument("--fail-on-severity", choices=sorted(SEVERITY_RANK), required=True, help="the scan's gate severity")
    args = parser.parse_args(argv)
    failures = gate_failures(args.report, args.exceptions, image=args.image, today=date.today(), fail_on_severity=args.fail_on_severity)
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print(f"Image scan for {args.image} is partial only for reviewed coverage exceptions; accepted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
