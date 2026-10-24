#!/usr/bin/env python3
"""Fail a pull request that adds or redefines a risky MCP server.

Diffs the MCP configs changed between two commits, collects the servers the
head adds or redefines, scans the checkout with agent-bom, and fails when one
of those servers is blocked by the launcher check, ships a known-malicious
package, or reaches a vulnerability at or above the severity threshold.
Standard library only; it runs from the action checkout.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

MCP_CONFIG_NAMES = {".mcp.json", "mcp.json"}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def is_mcp_config(path: str) -> bool:
    return PurePosixPath(path).name in MCP_CONFIG_NAMES


def _servers(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        return {}
    for key in ("mcpServers", "servers"):
        value = document.get(key)
        if isinstance(value, dict):
            return value
    return {}


def added_servers(base: Any, head: Any) -> list[str]:
    """Names of servers that are new in ``head`` or whose definition changed."""
    before = _servers(base)
    return sorted(name for name, definition in _servers(head).items() if before.get(name) != definition)


def _meets(severity: Any, threshold: str) -> bool:
    return SEVERITY_RANK.get(str(severity or "").lower(), 0) >= SEVERITY_RANK.get(threshold, 3)


def evaluate(report: dict[str, Any], names: list[str], *, threshold: str) -> dict[str, list[str]]:
    """Return ``{server: [reasons]}`` for every added server that is risky."""
    wanted = set(names)
    reasons: dict[str, list[str]] = {}
    for agent in report.get("agents") or []:
        for server in agent.get("mcp_servers") or []:
            name = str(server.get("name") or "")
            if name not in wanted:
                continue
            if server.get("security_blocked"):
                warnings = server.get("security_warnings") or ["blocked by the launcher check"]
                reasons.setdefault(name, []).append(f"blocked: {warnings[0]}")
            for package in server.get("packages") or []:
                if package.get("is_malicious"):
                    why = package.get("malicious_reason") or "known malicious package"
                    reasons.setdefault(name, []).append(f"malicious package {package.get('name')}: {why}")
    for row in report.get("blast_radius") or []:
        if not _meets(row.get("severity"), threshold):
            continue
        for name in set(row.get("affected_servers") or []) & wanted:
            reasons.setdefault(name, []).append(f"{str(row.get('severity')).upper()} {row.get('vulnerability_id')} in {row.get('package')}")
    for finding in report.get("findings") or []:
        if finding.get("finding_type") == "CVE" or not _meets(finding.get("severity"), threshold):
            continue
        for name in set(finding.get("affected_servers") or []) & wanted:
            reasons.setdefault(name, []).append(f"{str(finding.get('severity')).upper()} {finding.get('title')}")
    return reasons


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def _load_at(commit: str, path: str) -> Any:
    try:
        return json.loads(_git("show", f"{commit}:{path}"))
    except (subprocess.CalledProcessError, ValueError):
        return None


def _load_file(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--severity", default="high", choices=sorted(SEVERITY_RANK))
    parser.add_argument("--offline", action="store_true", help="Scan against the local vulnerability database only")
    args = parser.parse_args(argv)

    try:
        changed = [path for path in _git("diff", "--name-only", args.base, args.head).splitlines() if is_mcp_config(path)]
    except subprocess.CalledProcessError as exc:
        print(f"::error::MCP gate could not diff {args.base}..{args.head}: {exc.stderr.strip()}")
        return 1

    added: dict[str, list[str]] = {}
    for path in changed:
        head_doc = _load_at(args.head, path) if args.head else _load_file(path)
        for name in added_servers(_load_at(args.base, path), head_doc):
            added.setdefault(name, []).append(path)
    if not added:
        print("No MCP server added or changed.")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "mcp-gate.json"
        command = [sys.executable, "-m", "agent_bom", "scan", ".", "-f", "json", "-o", str(out), "-q"]
        if args.offline:
            command.append("--offline")
        subprocess.run(command, capture_output=True, text=True)
        if not out.is_file():
            print("::error::MCP gate scan produced no report")
            return 1
        report = json.loads(out.read_text(encoding="utf-8"))

    risky = evaluate(report, sorted(added), threshold=args.severity)
    print(f"MCP servers added or changed: {', '.join(sorted(added))}")
    for name in sorted(added):
        status = "RISKY" if name in risky else "ok"
        print(f"- `{name}` ({', '.join(added[name])}): {status}")
        for reason in risky.get(name, []):
            print(f"    {reason}")
    if risky:
        for name, why in sorted(risky.items()):
            print(f"::error title=agent-bom MCP gate::MCP server '{name}' added in {', '.join(added[name])} is risky: {why[0]}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
