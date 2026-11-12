#!/usr/bin/env python3
"""Render the Claude directory package without the local Codex manifest or evals.

Run after updating integrations/claude-code; --check refuses drift or extra files.
The repository marketplace continues to use the original shared plugin folder.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "integrations/claude-code"
DESTINATION = ROOT / "integrations/claude-directory"
RUNTIME_FILES = (
    ".claude-plugin/plugin.json",
    ".mcp.json",
    "mcp_launcher.py",
    "pyproject.toml",
    "uv.lock",
    "README.md",
    "assets/icon.png",
)
OVERRIDES = ROOT / "integrations/shared/claude-directory"


def bundle_files(source: Path = SOURCE) -> dict[str, bytes]:
    paths = [source / name for name in RUNTIME_FILES]
    paths.extend(sorted((source / "skills").glob("*/SKILL.md")))
    result = {}
    for path in paths:
        relative = path.relative_to(source)
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent.is_relative_to(source)):
            raise ValueError("Bundle inputs must be regular files without symbolic links")
        result[relative.as_posix()] = path.read_bytes()
    for target, template in {"README.md": "README.md", "skills/bom/SKILL.md": "bom.md"}.items():
        path = OVERRIDES / template
        if path.is_symlink():
            raise ValueError("Directory templates must not be symbolic links")
        result[target] = path.read_bytes()
    manifest = json.loads(result[".claude-plugin/plugin.json"])
    manifest["documentationUrl"] = manifest["documentationUrl"].replace("/claude-code/", "/claude-directory/")
    result[".claude-plugin/plugin.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return result


def stale_files(destination: Path, expected: dict[str, bytes]) -> list[str]:
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file() or path.is_symlink()}
    return sorted(
        (actual - expected.keys())
        | {
            name
            for name, content in expected.items()
            if not (destination / name).is_file() or (destination / name).is_symlink() or (destination / name).read_bytes() != content
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = bundle_files()
    if args.check:
        stale = stale_files(DESTINATION, expected)
        if stale:
            print("Claude directory bundle is stale: " + ", ".join(stale))
            return 1
        print("Claude directory bundle matches its source")
        return 0
    for name, content in expected.items():
        target = DESTINATION / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    print(f"Rendered {len(expected)} Claude directory files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
