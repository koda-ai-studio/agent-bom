"""List repository files the way `git ls-files` does, also inside containers.

CI containers (the Alpine shard) mount the checkout with a different owner, so
plain `git ls-files` exits 128 on git's ownership check. Mark the root safe for
this one call, and walk the tree if git is unavailable.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_SKIP_DIRS = {".git", "node_modules", ".next", "out", ".venv", "__pycache__"}


def tracked_files(root: Path, *paths: str) -> list[str]:
    """Return repository-relative POSIX paths of tracked files under ``paths``."""
    try:
        listed = subprocess.run(
            ["git", "-c", f"safe.directory={root}", "ls-files", "-z", "--", *paths],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
        return [item.decode() for item in listed.split(b"\0") if item]
    except (OSError, subprocess.CalledProcessError):
        found: list[str] = []
        for scope in paths:
            target = root / scope
            if target.is_file():
                found.append(scope)
                continue
            for path in sorted(target.rglob("*")) if target.is_dir() else []:
                if path.is_file() and not _SKIP_DIRS.intersection(path.relative_to(root).parts):
                    found.append(path.relative_to(root).as_posix())
        return found
