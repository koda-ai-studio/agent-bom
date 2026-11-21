#!/usr/bin/env python3
"""Measure agent-bom's dependency accuracy on public repositories at pinned commits.

For each repository in the manifest (``docs/accuracy/real-repos.json``):

1. download the GitHub source archive of the pinned commit;
2. run ``agent-bom scan <dir> -f json -o <out>`` with an isolated HOME and
   ``AGENT_BOM_STATE_DIR`` (the real ``~/.agent-bom`` is never read or written);
3. build an independent ground truth: parse each judged lockfile with the
   parsers in ``real_repo_accuracy_lockfiles`` and query every
   ``name@version`` at the OSV API, then fetch each advisory for its aliases;
4. compare packages and advisories, classify every miss and extra, and write
   a machine-readable result.

Manifests without a lockfile (Gradle without ``gradle.lockfile``,
``setup.cfg``, Maven with BOM imports) are listed as not independently
verified: the scan's numbers are reported, but no ground truth is invented.

Usage::

    python scripts/measure_real_repo_accuracy.py --sync-db
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from scripts.real_repo_accuracy_compare import (
        AdvisoryContext,
        PackageKey,
        compare_advisories,
        compare_packages,
        finding_ids,
        package_key,
    )
    from scripts.real_repo_accuracy_lockfiles import parse_lockfile
except ModuleNotFoundError:  # run as ``python scripts/measure_real_repo_accuracy.py``
    from real_repo_accuracy_compare import (  # type: ignore[no-redef]
        AdvisoryContext,
        PackageKey,
        compare_advisories,
        compare_packages,
        finding_ids,
        package_key,
    )
    from real_repo_accuracy_lockfiles import parse_lockfile  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "docs" / "accuracy" / "real-repos.json"
DEFAULT_OUTPUT = ROOT / "docs" / "accuracy" / "real-repos-results.json"
OSV_API = "https://api.osv.dev/v1"
OSV_BATCH = 500
SYNC_ECOSYSTEMS = ("pypi", "npm", "go", "maven", "crates.io")
PURL_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "golang": "Go", "cargo": "crates.io", "maven": "Maven"}
SCAN_TIMEOUT_SECONDS = 1800


# ---------------------------------------------------------------- HTTP / OSV


def _http_json(url: str, payload: dict[str, Any] | None = None, attempts: int = 5) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json", "User-Agent": "real-repo-accuracy-measurement"}
    for attempt in range(attempts):
        request = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310 - fixed https URL
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code not in (429, 500, 502, 503, 504) or attempt == attempts - 1:
                raise
        except urllib.error.URLError:
            if attempt == attempts - 1:
                raise
        time.sleep(2**attempt)
    raise RuntimeError(f"unreachable: {url}")


def _query_one(query: dict[str, Any], vulns: list[dict[str, Any]], token: str) -> None:
    """Follow OSV pagination for a single query whose batch result was truncated."""
    while token:
        page = _http_json(f"{OSV_API}/query", {**query, "page_token": token}) or {}
        vulns.extend(page.get("vulns") or [])
        token = page.get("next_page_token", "")


def osv_affected_ids(packages: set[tuple[str, str, str]]) -> dict[tuple[str, str, str], set[str]]:
    """OSV advisory IDs affecting each exact ``(ecosystem, name, version)``."""
    ordered = sorted(packages)
    result: dict[tuple[str, str, str], set[str]] = {}
    for start in range(0, len(ordered), OSV_BATCH):
        chunk = ordered[start : start + OSV_BATCH]
        queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]
        response = _http_json(f"{OSV_API}/querybatch", {"queries": queries}) or {}
        for package, query, item in zip(chunk, queries, response.get("results", []), strict=True):
            vulns = list(item.get("vulns") or [])
            _query_one(query, vulns, item.get("next_page_token", ""))
            result[package] = {str(v["id"]).upper() for v in vulns}
    return result


def fetch_records(ids: set[str], cache: dict[str, Any]) -> dict[str, Any]:
    """OSV records by upper-case ID (``None`` when OSV has no such ID), cached across repositories."""
    missing = sorted(i for i in ids if i not in cache)
    with ThreadPoolExecutor(max_workers=8) as pool:
        for advisory, record in zip(missing, pool.map(_fetch_record, missing), strict=True):
            cache[advisory] = record
    return {i: cache[i] for i in ids}


def _fetch_record(advisory: str) -> dict[str, Any] | None:
    record = _http_json(f"{OSV_API}/vulns/{urllib.parse.quote(advisory, safe='')}")
    if not record:
        return None
    keep = ("id", "aliases", "withdrawn", "published", "modified")
    return {k: record[k] for k in keep if k in record}


# ------------------------------------------------------------- repo + scan


def fetch_commit(url: str, commit: str, dest: Path) -> None:
    """Download and safely extract the GitHub source archive of one exact commit."""
    owner_repo = urllib.parse.urlparse(url).path.strip("/").removesuffix(".git")
    archive = f"https://codeload.github.com/{owner_repo}/tar.gz/{commit}"
    request = urllib.request.Request(archive, headers={"User-Agent": "real-repo-accuracy-measurement"})
    with urllib.request.urlopen(request, timeout=300) as response:  # nosec B310 - fixed https URL
        payload = response.read()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
        members = []
        for member in tar.getmembers():
            _, _, rest = member.name.partition("/")
            if rest:
                member.name = rest
                members.append(member)
        tar.extractall(dest, members=members, filter="data")


def isolated_env(state_dir: Path) -> dict[str, str]:
    env = dict(os.environ)
    home = state_dir / "home"
    home.mkdir(parents=True, exist_ok=True)
    env.update({"HOME": str(home), "AGENT_BOM_STATE_DIR": str(state_dir)})
    env.pop("AGENT_BOM_DB_PATH", None)
    return env


def agent_bom(python: str, args: list[str], env: dict[str, str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [python, "-m", "agent_bom", *args], env=env, text=True, capture_output=True, check=False, **kwargs
    )


def run_scan(python: str, repo_dir: Path, out: Path, env: dict[str, str]) -> dict[str, Any]:
    proc = agent_bom(python, ["scan", str(repo_dir), "-f", "json", "-o", str(out)], env, timeout=SCAN_TIMEOUT_SECONDS)
    if proc.returncode not in (0, 1) or not out.exists():
        raise RuntimeError(f"agent-bom scan exited {proc.returncode}: {proc.stderr[-2000:]}")
    report = json.loads(out.read_text(encoding="utf-8"))
    report["_exit_code"] = proc.returncode
    return report


def _purl_key(purl: str) -> PackageKey | None:
    if not purl.startswith("pkg:"):
        return None
    kind, _, rest = purl[4:].partition("/")
    ecosystem = PURL_ECOSYSTEMS.get(kind)
    rest = rest.split("?", 1)[0].split("#", 1)[0]
    name, at, version = rest.rpartition("@")
    if not ecosystem or not at:
        return None
    name = urllib.parse.unquote(name)
    if ecosystem == "Maven":
        name = name.replace("/", ":")
    return package_key(ecosystem, name, urllib.parse.unquote(version))


def scan_packages(report: dict[str, Any]) -> set[PackageKey]:
    return {key for p in report.get("packages") or [] if (key := _purl_key(str(p.get("purl") or "")))}


def scan_findings(report: dict[str, Any]) -> dict[PackageKey, list[set[str]]]:
    found: dict[PackageKey, list[set[str]]] = {}
    for finding in report.get("findings") or []:
        asset = finding.get("asset") or {}
        if finding.get("finding_category") != "vulnerability" or asset.get("asset_type") != "package":
            continue
        key = _purl_key(str(asset.get("identifier") or ""))
        if key and (ids := finding_ids(finding)):
            found.setdefault(key, []).append(ids)
    return found


def _scrub(value: Any, repo_dir: Path) -> Any:
    """Replace the local checkout path so results do not record the measuring machine's layout."""
    return value.replace(str(repo_dir), "<repo>") if isinstance(value, str) else value


def scan_summary(report: dict[str, Any], repo_dir: Path) -> dict[str, Any]:
    run = report.get("scan_run") or {}
    warning_keys = ("kind", "ecosystem", "reason", "detail", "package_count")
    return {
        "exit_code": report.get("_exit_code"),
        "outcome": run.get("outcome"),
        "issues": [
            {
                "code": i.get("code"),
                "affects_coverage": i.get("affects_coverage"),
                "message": _scrub(i.get("message"), repo_dir),
            }
            for i in run.get("issues") or []
        ],
        "coverage_warnings": [{k: _scrub(w.get(k), repo_dir) for k in warning_keys} for w in report.get("coverage_warnings") or []],
    }


# ---------------------------------------------------------------- measuring


def ground_truth(repo_dir: Path, lockfiles: list[dict[str, str]]) -> tuple[set[tuple[str, str, str]], list[str]]:
    packages: set[tuple[str, str, str]] = set()
    skipped: list[str] = []
    for entry in lockfiles:
        parsed = parse_lockfile(repo_dir / entry["path"], entry["format"])
        packages |= parsed.packages
        skipped.extend(f"{entry['path']}: {item}" for item in parsed.skipped)
    return packages, skipped


def measure_ecosystem(
    group: dict[str, Any], repo_dir: Path, report: dict[str, Any], db_synced_at: str, cache: dict[str, Any]
) -> dict[str, Any]:
    raw, skipped = ground_truth(repo_dir, group["lockfiles"])
    by_raw = osv_affected_ids(raw)
    expected: dict[PackageKey, set[str]] = {}
    for triple, ids in by_raw.items():
        expected.setdefault(package_key(*triple), set()).update(ids)
    found_packages = {k for k in scan_packages(report) if k[0] == group["ecosystem"]}
    findings = {k: v for k, v in scan_findings(report).items() if k in expected}
    all_ids = set().union(*expected.values(), *(i for v in findings.values() for i in v))
    records = fetch_records(all_ids, cache)
    ctx = AdvisoryContext(records=records, found_packages=found_packages, db_synced_at=db_synced_at)
    advisories = compare_advisories(expected, findings, ctx)
    return {
        "ecosystem": group["ecosystem"],
        "lockfiles": [entry["path"] for entry in group["lockfiles"]],
        "verified": True,
        "packages": {**compare_packages(set(expected), found_packages), "skipped_non_registry": skipped},
        "advisories": {
            "expected": advisories.expected,
            "matched": advisories.matched,
            "missed": len(advisories.missed),
            "extra": len(advisories.extra),
            "unexplained_missed": advisories.unexplained_missed,
            "false_positive_candidates": advisories.false_positive_candidates,
        },
        "missed": advisories.missed,
        "extra": advisories.extra,
    }


def unverified_summary(entry: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    ecosystem = entry["ecosystem"]
    packages = {k for k in scan_packages(report) if k[0] == ecosystem}
    advisories = {(k, frozenset(ids)) for k, v in scan_findings(report).items() if k[0] == ecosystem for ids in v}
    # Advisories on a version picked from a declared range are reported apart from findings.
    possibly = {
        (key, str(item.get("id")))
        for item in report.get("possibly_affected") or []
        if (key := _purl_key(str((item.get("package") or {}).get("purl") or ""))) and key[0] == ecosystem
    }
    return {
        "ecosystem": ecosystem,
        "manifests": entry["manifests"],
        "verified": False,
        "reason": entry["reason"],
        "packages_found": len(packages),
        "advisories_reported": len(advisories),
        "possibly_affected_reported": len(possibly),
    }


def measure_repo(repo: dict[str, Any], args: argparse.Namespace, env: dict[str, str], cache: dict[str, Any]) -> dict:
    slug = f"{repo['name'].replace('/', '__')}-{repo['commit'][:12]}"
    repo_dir = args.work_dir / "repos" / slug
    if not repo_dir.exists():
        fetch_commit(repo["url"], repo["commit"], repo_dir)
    report = run_scan(args.python, repo_dir, args.work_dir / "scans" / f"{slug}.json", env)
    synced = str((report.get("vuln_data_freshness") or {}).get("last_updated") or "")
    return {
        "name": repo["name"],
        "url": repo["url"],
        "commit": repo["commit"],
        "scan": scan_summary(report, repo_dir),
        "advisory_db_synced_at": synced,
        "ecosystems": [measure_ecosystem(g, repo_dir, report, synced, cache) for g in repo.get("verified", [])],
        "unverified": [unverified_summary(u, report) for u in repo.get("unverified", [])],
    }


def totals(repos: list[dict[str, Any]]) -> dict[str, int]:
    keys = ("expected", "matched", "missed", "extra", "unexplained_missed", "false_positive_candidates")
    out = {k: 0 for k in keys}
    out.update(packages_expected=0, packages_found=0)
    for repo in repos:
        for eco in repo["ecosystems"]:
            for k in keys:
                out[k] += eco["advisories"][k]
            out["packages_expected"] += eco["packages"]["expected"]
            out["packages_found"] += eco["packages"]["found"]
    return out


def unexplained(repos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flagged: list[dict[str, Any]] = []
    for repo in repos:
        for eco in repo["ecosystems"]:
            for kind, items, bad in (
                ("missed", eco["missed"], {"unexplained", "package_not_found"}),
                ("extra", eco["extra"], {"osv_does_not_list_version"}),
            ):
                flagged.extend({"repo": repo["name"], "kind": kind, **i} for i in items if i["reason"] in bad)
    return flagged


def sync_db(python: str, env: dict[str, str]) -> None:
    args = ["db", "update", "--source", "osv"]
    for ecosystem in SYNC_ECOSYSTEMS:
        args += ["--osv-ecosystem", ecosystem]
    proc = agent_bom(python, args, env)
    if proc.returncode != 0:
        raise RuntimeError(f"advisory DB sync failed ({proc.returncode}): {proc.stderr[-2000:]}")


def agent_bom_version(python: str, env: dict[str, str]) -> str:
    proc = agent_bom(python, ["--version"], env)
    first = (proc.stdout or proc.stderr).strip().splitlines()[0]
    return first.removeprefix("agent-bom ").strip()


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--work-dir", type=Path, help="Scratch directory (default: a new temp dir).")
    parser.add_argument("--python", default=sys.executable, help="Python that runs `-m agent_bom`.")
    parser.add_argument("--sync-db", action="store_true", help="Sync the OSV advisory DB into the work dir first.")
    parser.add_argument("--repo", action="append", default=[], help="Only measure these repositories.")
    args = parser.parse_args(argv)
    args.work_dir = (args.work_dir or Path(tempfile.mkdtemp(prefix="real-repo-accuracy-"))).resolve()
    return args


def _select(manifest: dict[str, Any], names: list[str]) -> list[dict[str, Any]]:
    repos = manifest["repositories"]
    return [r for r in repos if r["name"] in names] if names else repos


def main(argv: list[str] | None = None, log: Callable[[str], None] = print) -> int:
    args = parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    (args.work_dir / "scans").mkdir(parents=True, exist_ok=True)
    env = isolated_env(args.work_dir / "agent-bom-state")
    if args.sync_db:
        log("syncing the OSV advisory database")
        sync_db(args.python, env)
    cache: dict[str, Any] = {}
    repos = []
    for repo in _select(manifest, args.repo):
        log(f"measuring {repo['name']} @ {repo['commit'][:12]}")
        repos.append(measure_repo(repo, args, env, cache))
    result = {
        "agent_bom_version": agent_bom_version(args.python, env),
        "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "ground_truth": "OSV API (api.osv.dev) queried per name@version from independently parsed lockfiles",
        "totals": totals(repos),
        "unexplained_differences": unexplained(repos),
        "repositories": repos,
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    log(json.dumps(result["totals"]))
    log(f"wrote {args.output} (work dir: {args.work_dir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
