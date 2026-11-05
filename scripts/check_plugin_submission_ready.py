#!/usr/bin/env python3
"""Refuse a plugin directory submission that would ship stale pins or draft legal pages.

Not part of ``make preflight``: it stays red until a fixed release is cut and the
owner approves the legal pages. Run ``make plugin-submission-check`` before opening
either directory portal (see docs/PLUGIN_SUBMISSION.md).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The first release carrying the fixes that 0.113.2 lacks. Raise it when a release
# fixes something a reviewer would hit.
MINIMUM_RELEASE = "0.114.0"

MANIFESTS = (
    "integrations/claude-code/.claude-plugin/plugin.json",
    "integrations/claude-code/.codex-plugin/plugin.json",
    "integrations/agent-bom-guard/.claude-plugin/plugin.json",
    "integrations/codex/plugin.json",
    "integrations/codex/.codex-plugin/plugin.json",
)
_PIN = re.compile(r"agent-bom(?:\[[a-z]+\])?==(\d[^\s\"',`]*)")
_LEGAL_PAGES = ("site-docs/privacy.md", "site-docs/terms.md")
_REVIEW_CASES = (
    "integrations/claude-code/evals/review-cases.json",
    "integrations/agent-bom-guard/review-cases.json",
    "integrations/codex/review-cases.json",
)


def at_least(version: str, floor: str) -> bool:
    def parts(value: str) -> tuple[int, ...]:
        return tuple(int(piece) for piece in value.split("."))

    if not re.fullmatch(r"\d+(\.\d+)*", version):
        return False
    return parts(version) >= parts(floor)


def _pin_paths(root: Path) -> list[Path]:
    paths = [root / "integrations/claude-code/pyproject.toml", root / "integrations/claude-code/README.md"]
    for plugin in ("claude-code", "codex"):
        paths.extend(sorted((root / "integrations" / plugin / "skills").glob("*/SKILL.md")))
    return paths


def pinned_versions(root: Path) -> dict[str, list[Path]]:
    """Every ``agent-bom==`` pin in the shipped text, by version."""
    found: dict[str, list[Path]] = {}
    for path in _pin_paths(root):
        if path.is_file():
            for version in set(_PIN.findall(path.read_text(encoding="utf-8"))):
                found.setdefault(version, []).append(path)
    return found


def _locked_version(root: Path) -> str | None:
    lock = root / "integrations/claude-code/uv.lock"
    if not lock.is_file():
        return None
    match = re.search(r'name = "agent-bom"\nversion = "([^"]+)"', lock.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def _version_problems(root: Path) -> list[str]:
    problems = []
    for manifest in MANIFESTS:
        path = root / manifest
        version = json.loads(path.read_text(encoding="utf-8")).get("version", "") if path.is_file() else ""
        if not at_least(str(version), MINIMUM_RELEASE):
            problems.append(f"{manifest}: version {version or '(missing)'} is below {MINIMUM_RELEASE}; cut the release first")
    for version, paths in pinned_versions(root).items():
        if not at_least(version, MINIMUM_RELEASE):
            names = ", ".join(str(path.relative_to(root)) for path in paths[:3])
            problems.append(f"agent-bom=={version} is pinned below {MINIMUM_RELEASE} in {names} and {max(len(paths) - 3, 0)} more")
    locked = _locked_version(root)
    if locked is None or not at_least(locked, MINIMUM_RELEASE):
        problems.append(f"integrations/claude-code/uv.lock locks agent-bom {locked or '(missing)'}, below {MINIMUM_RELEASE}")
    return problems


def _page_problems(root: Path) -> list[str]:
    problems = []
    for page in _LEGAL_PAGES:
        path = root / page
        if not path.is_file():
            problems.append(f"{page} is missing")
        elif re.search(r"\bDRAFT\b", path.read_text(encoding="utf-8")):
            problems.append(f"{page} is still marked as a draft; the owner must approve it and remove the marker")
    return problems


def _review_problems(root: Path) -> list[str]:
    problems = []
    for relative in _REVIEW_CASES:
        path = root / relative
        if not path.is_file():
            problems.append(f"{relative} (review-cases) is missing")
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if len(data.get("positive", [])) != 5 or len(data.get("negative", [])) != 3:
            problems.append(f"{relative} (review-cases) needs exactly 5 positive and 3 negative cases")
    return problems


def problems(root: Path) -> list[str]:
    return [*_version_problems(root), *_page_problems(root), *_review_problems(root)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    found = problems(args.root)
    for problem in found:
        print(f"BLOCKED: {problem}")
    if found:
        print(f"{len(found)} problem(s): do not submit. See docs/PLUGIN_SUBMISSION.md.", file=sys.stderr)
        return 1
    print("Plugin submission check passed. The portal runs more checks than this.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
