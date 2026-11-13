"""Installed Python distributions on a filesystem: where they live and what they are.

Reads ``*.dist-info/METADATA`` and ``*.egg-info`` headers only; nothing is imported or run.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from agent_bom.models import Package

logger = logging.getLogger(__name__)


def parse_site_packages(site_packages_dir: Path) -> list[Package]:
    """Parse installed Python packages from a ``site-packages`` or
    ``dist-packages`` directory by reading ``.dist-info/METADATA`` files.

    Works on live systems and mounted disk snapshots.

    Args:
        site_packages_dir: Path to a ``site-packages`` or ``dist-packages``
            directory.

    Returns:
        List of :class:`~agent_bom.models.Package` objects with
        ``ecosystem="pypi"``.
    """
    if not site_packages_dir.exists():
        return []

    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()

    metadata_files = [d / "METADATA" for d in sorted(site_packages_dir.glob("*.dist-info"))]
    # setuptools-era installs: an .egg-info directory, or a single .egg-info file.
    for egg_info in sorted(site_packages_dir.glob("*.egg-info")):
        metadata_files.append(egg_info / "PKG-INFO" if egg_info.is_dir() else egg_info)
    for metadata_file in metadata_files:
        if not metadata_file.is_file():
            continue

        name = ""
        version = ""
        try:
            for line in metadata_file.read_text(errors="replace", encoding="utf-8").splitlines():
                if line.startswith("Name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("Version:"):
                    version = line.split(":", 1)[1].strip()
                elif line.startswith("") and name and version:
                    # Empty line signals end of headers
                    break
        except OSError:
            continue

        if name and version:
            key = (name.lower(), version)
            if key not in seen:
                seen.add(key)
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        purl=f"pkg:pypi/{name.lower()}@{version}",
                        is_direct=True,
                    )
                )

    return packages


_SITE_DIR_NAMES = frozenset({"site-packages", "dist-packages"})
_SITE_DIR_PATTERNS = (
    # System and image prefixes.
    "usr/lib/python*/site-packages",
    "usr/lib/python*/dist-packages",
    "usr/lib64/python*/site-packages",
    "usr/local/lib/python*/site-packages",
    "usr/local/lib/python*/dist-packages",
    "opt/conda/lib/python*/site-packages",
    # The target is itself an environment prefix: a venv, a conda env, a Windows venv.
    "lib/python*/site-packages",
    "lib64/python*/site-packages",
    "Lib/site-packages",
)
_SITE_WALK_MAX_DEPTH = 8
_SITE_WALK_MAX_DIRS = 50_000
_SITE_WALK_SKIP = frozenset({".git", "node_modules", "__pycache__", "proc", "sys", "dev"})


def _holds_dist_info(directory: Path) -> bool:
    try:
        return any(child.name.endswith(".dist-info") and child.is_dir() for child in directory.iterdir())
    except OSError:
        return False


def _walk_for_site_dirs(root: Path) -> list[Path]:
    """Bounded walk for site-packages/dist-packages outside the known prefixes."""
    found: list[Path] = []
    visited = 0
    root_depth = len(root.parts)
    for current, dirnames, _files in os.walk(root, followlinks=False):
        visited += 1
        if visited > _SITE_WALK_MAX_DIRS:
            logger.debug("native-dir: stopped looking for site-packages after %d directories under %s", visited, root)
            break
        here = Path(current)
        if here.name in _SITE_DIR_NAMES:
            found.append(here)
            dirnames[:] = []
            continue
        if len(here.parts) - root_depth >= _SITE_WALK_MAX_DEPTH:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in _SITE_WALK_SKIP]
    return found


def python_site_dirs(root: Path) -> list[Path]:
    """Directories under *root* holding installed Python distributions.

    Covers system prefixes, a venv/conda/Windows-venv root, a bare site-packages
    directory passed as the target, and, when none of those match, a bounded walk
    so installed metadata is never silently missed.
    """
    candidates: list[Path] = []
    if root.name in _SITE_DIR_NAMES or _holds_dist_info(root):
        candidates.append(root)
    for pattern in _SITE_DIR_PATTERNS:
        candidates.extend(sorted(root.glob(pattern)))
    if not candidates:
        candidates = _walk_for_site_dirs(root)
    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved not in seen and candidate.is_dir():
            seen.add(resolved)
            unique.append(candidate)
    return unique
