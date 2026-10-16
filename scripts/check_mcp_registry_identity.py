#!/usr/bin/env python3
"""Check official registry ownership locally, and optionally in exact PyPI metadata."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def validate_identity(manifest: dict[str, Any], repository: str, description: str) -> None:
    """OIDC grants the repository owner's namespace; PyPI must attest the same name."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid GitHub repository identity")
    owner, project = repository.split("/")
    name = f"io.github.{owner}/{project}"
    if manifest.get("name") != name:
        raise ValueError(f"MCP namespace must match the OIDC repository owner: {name}")
    if manifest.get("repository") != {"url": f"https://github.com/{repository}", "source": "github"}:
        raise ValueError("MCP repository metadata must match the publishing repository")
    if not re.search(r"(?<!\S)mcp-name:\s*" + re.escape(name) + r"(?=\s|<|-->|$)", description):
        raise ValueError(
            "PyPI README ownership marker does not match the MCP name; publish a new package version before registry publication"
        )


def check_local_identity(root: Path = ROOT, repository: str | None = None) -> dict[str, Any]:
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    repository = repository or project["urls"]["Repository"].removeprefix("https://github.com/")
    manifest = json.loads((root / "integrations/mcp-registry/server.json").read_text())
    readme = project["readme"]
    if isinstance(readme, dict):
        readme = readme["file"]
    for path in ("README.md", readme):
        validate_identity(manifest, repository, (root / path).read_text())
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", help="GitHub owner/repository from the publishing workflow")
    parser.add_argument("--published", action="store_true", help="Also require ownership in the exact published PyPI package version")
    args = parser.parse_args(argv)
    try:
        manifest = check_local_identity(repository=args.repository)
        if args.published:
            packages = manifest["packages"]
            if len(packages) != 1 or packages[0]["registryType"] != "pypi" or packages[0]["identifier"] != "agent-bom":
                raise ValueError("expected one agent-bom PyPI package")
            version = packages[0]["version"]
            if version != manifest["version"] or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
                raise ValueError("registry and package versions must match a stable release")
            with urllib.request.urlopen(f"https://pypi.org/pypi/agent-bom/{version}/json", timeout=30) as response:
                info = json.load(response)["info"]
            if info.get("name") != "agent-bom" or info.get("version") != version:
                raise ValueError("PyPI returned a different package identity or version")
            repository = manifest["repository"]["url"].removeprefix("https://github.com/")
            validate_identity(manifest, repository, info["description"])
    except ValueError as exc:
        print(f"MCP Registry identity check failed: {exc}")
        return 1
    except (OSError, urllib.error.URLError, KeyError, TypeError):
        print("MCP Registry identity check failed: ownership metadata unavailable or malformed")
        return 1
    print("MCP Registry identity and ownership marker verified" + (" in the published package" if args.published else " locally"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
