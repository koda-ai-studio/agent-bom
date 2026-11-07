#!/usr/bin/env python3
"""Accuracy lane: scan pinned public targets and assert the report's structure.

Repositories are fetched at an exact commit and images are addressed by digest.
Target code is data: it is fetched with git only, never installed or executed.

Sentinel advisories are independent ground truth, each confirmed against the OSV
API for the exact version the target pins, so a scan that silently loses
detection fails here even when it exits cleanly.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import LaneResult, agent_bom_command, run_measured, tail  # noqa: E402


@dataclass(frozen=True)
class Target:
    name: str
    kind: str
    ref: str
    sentinels: tuple[str, ...]
    min_packages: int
    commit: str = ""


TARGETS = {
    target.name: target
    for target in (
        Target(
            name="langchain-v0.0.300",
            kind="repo",
            ref="https://github.com/langchain-ai/langchain",
            commit="3cb460d5d888866a83f737034bcc78daf0d6fe4a",
            # libs/langchain/poetry.lock pins aiohttp 3.8.5 and cryptography 41.0.3.
            sentinels=("CVE-2024-23334", "CVE-2023-49083"),
            min_packages=100,
        ),
        Target(
            name="juice-shop-v15.0.0",
            kind="repo",
            ref="https://github.com/juice-shop/juice-shop",
            commit="6c95744753a77f7302f8db1e2c811e3c39d40ff7",
            # package.json pins jsonwebtoken 0.4.0 and express-jwt 0.1.3 exactly.
            sentinels=("CVE-2015-9235", "CVE-2020-15084"),
            min_packages=50,
        ),
        Target(
            name="nginx-1.21.6",
            kind="image",
            ref="nginx:1.21.6@sha256:2bcabc23b45489fb0885d69a06ba1d648aeda973fae7bb981bafbb884165e514",
            # Debian 11 base layer of the image ships zlib with this fix missing.
            sentinels=("CVE-2022-37434",),
            min_packages=50,
        ),
        Target(
            name="redis-7.0.11",
            kind="image",
            ref="redis:7.0.11@sha256:1008c73f08e9f913868e2fa2e843212b62ea5bf3c66435d87bc7a6207bc0f1b4",
            # Debian 12 base layer of the image predates the glibc tunables fix.
            sentinels=("CVE-2023-4911",),
            min_packages=50,
        ),
    )
}


def advisory_ids(report: dict[str, Any]) -> set[str]:
    """Every advisory id and alias the report names, normalised to upper case."""
    ids: set[str] = set()
    for row in report.get("blast_radius") or []:
        if row.get("vulnerability_id"):
            ids.add(str(row["vulnerability_id"]).upper())
        ids.update(str(alias).upper() for alias in row.get("aliases") or [])
    return ids


def _unique_rows(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in report.get("blast_radius") or []:
        rows.setdefault(str(row.get("vulnerability_id")), row)
    return rows


def measurements(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary") or {}
    finding_summary = report.get("finding_summary") or {}
    unique = _unique_rows(report)
    severity = Counter(str(row.get("severity") or "unknown").lower() for row in unique.values())
    inventory = report.get("project_inventory") or {}
    return {
        "packages": summary.get("total_packages", 0),
        "unique_advisories": len(unique),
        "cve_ids": sum(1 for key in unique if key.upper().startswith("CVE-")),
        "vulnerability_occurrences": summary.get("vulnerability_occurrences", summary.get("total_vulnerabilities", 0)),
        "advisory_severity": dict(severity),
        "finding_severity": finding_summary.get("by_severity", {}),
        "finding_types": finding_summary.get("by_type", {}),
        "unknown_severity": severity.get("unknown", 0),
        "agents": summary.get("total_agents", 0),
        "mcp_servers": summary.get("total_mcp_servers", 0),
        "credential_findings": len(report.get("credential_risk_ranking") or []),
        "grade": report.get("posture_grade", ""),
        "outcome": (report.get("scan_run") or {}).get("outcome", ""),
        "scan_run_issues": len((report.get("scan_run") or {}).get("issues") or []),
        "coverage_warnings": len(report.get("coverage_warnings") or []),
        "lockfile_backed_packages": inventory.get("lockfile_backed_packages"),
        "declaration_only_packages": inventory.get("declaration_only_packages"),
    }


def assert_report(result: LaneResult, target: Target, report: dict[str, Any], *, returncode: int) -> None:
    summary = report.get("summary") or {}
    finding_summary = report.get("finding_summary") or {}
    by_severity = finding_summary.get("by_severity") or {}
    measured = measurements(report)
    result.check("exit_code_is_a_verdict", returncode in (0, 1), f"exit {returncode}")
    result.check(
        "inventory_has_packages",
        summary.get("total_packages", 0) >= target.min_packages,
        f"{summary.get('total_packages')} >= {target.min_packages}",
    )
    result.check("reports_advisories", measured["unique_advisories"] > 0, measured["unique_advisories"])
    result.check(
        "severity_counts_sum_to_total",
        sum(by_severity.values()) == finding_summary.get("total"),
        f"{by_severity} vs total {finding_summary.get('total')}",
    )
    result.check("grade_present", bool(measured["grade"]), measured["grade"])
    result.check("scan_outcome_recorded", measured["outcome"] in {"complete", "partial", "failed"}, measured["outcome"])
    found = advisory_ids(report)
    missing = sorted(set(target.sentinels) - found)
    result.check(
        "known_advisories_found", not missing, f"missing {missing} of {list(target.sentinels)}" if missing else list(target.sentinels)
    )


def fetch_repo(target: Target, destination: Path) -> None:
    git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-C", str(destination)]
    env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"}
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(destination)], check=True, env=env)  # noqa: S603, S607
    subprocess.run([*git, "fetch", "-q", "--depth=1", target.ref, target.commit], check=True, env=env)  # noqa: S603
    subprocess.run([*git, "checkout", "-q", "FETCH_HEAD"], check=True, env=env)  # noqa: S603
    head = subprocess.run([*git, "rev-parse", "HEAD"], check=True, env=env, capture_output=True, text=True).stdout.strip()  # noqa: S603
    if head != target.commit:
        raise RuntimeError(f"fetched {head}, expected {target.commit}")


def scan_command(target: Target, source: Path | None, output: Path) -> list[str]:
    if target.kind == "repo":
        return agent_bom_command("scan", str(source), "-f", "json", "-o", str(output))
    return agent_bom_command("image", target.ref, "--pull-mode", "registry", "-f", "json", "-o", str(output))


def run_target(target: Target, workdir: Path) -> LaneResult:
    result = LaneResult("accuracy", target.name)
    result.measurements["target"] = {"kind": target.kind, "ref": target.ref, "commit": target.commit}
    source = None
    if target.kind == "repo":
        source = workdir / "target"
        fetch_repo(target, source)
    output = workdir / "report.json"
    env = {**os.environ, "HOME": str(workdir / "home"), "USERPROFILE": str(workdir / "home"), "AGENT_BOM_SKIP_UPDATE_CHECK": "1"}
    (workdir / "home").mkdir(parents=True, exist_ok=True)
    run = run_measured(scan_command(target, source, output), env=env, cwd=workdir, timeout=1500)
    result.measurements.update(duration_seconds=run.seconds, peak_rss_mb=run.peak_rss_mb, exit_code=run.returncode)
    if not result.check(
        "report_written", output.is_file() and not run.timed_out, f"exit {run.returncode}, timed_out={run.timed_out}\n{tail(run.stderr)}"
    ):
        return result
    report = json.loads(output.read_text(encoding="utf-8"))
    result.measurements.update(measurements(report))
    print(tail(run.stdout, 15))
    assert_report(result, target, report, returncode=run.returncode)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="qualification-accuracy-") as workdir:
        return run_target(TARGETS[args.target], Path(workdir)).write()


if __name__ == "__main__":
    raise SystemExit(main())
