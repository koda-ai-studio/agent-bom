"""Read a project's own virtualenv: exact installed versions, offline, without running code.

The venv is a child directory of the project root holding ``pyvenv.cfg``
(``.venv``, ``venv`` and ``env`` are tried first), or ``$VIRTUAL_ENV`` when it
lies inside the project root. Only ``*.dist-info/METADATA`` and
``*.egg-info/PKG-INFO`` headers are read; links that resolve outside the
project root are skipped and the walk is bounded.
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name

from agent_bom.core.settings import env_raw
from agent_bom.parsers.oci_metadata import _parse_rfc822_name_version

logger = logging.getLogger(__name__)

MAX_DISTRIBUTIONS = 5_000
_MAX_CHILDREN = 256
_MAX_METADATA_BYTES = 256 * 1024
_PREFERRED_NAMES = (".venv", "venv", "env")
_METADATA_FILES = (("*.dist-info", "METADATA"), ("*.egg-info", "PKG-INFO"))


@dataclass
class InstalledDistribution:
    name: str
    version: str
    metadata_path: Path


@dataclass
class VenvInventory:
    venv: Path
    distributions: list[InstalledDistribution] = field(default_factory=list)
    truncated: bool = False


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def _candidates(directory: Path) -> list[Path]:
    candidates = [Path(active)] if (active := env_raw("VIRTUAL_ENV")) else []
    candidates += [directory / name for name in _PREFERRED_NAMES]
    try:
        children = sorted(child for _, child in zip(range(_MAX_CHILDREN), directory.iterdir()))
    except OSError:
        children = []
    return candidates + [child for child in children if child.name not in _PREFERRED_NAMES]


def find_project_venv(directory: Path) -> Path | None:
    """The single virtualenv owned by *directory*, or ``None``."""
    root = directory.resolve()
    for candidate in _candidates(directory):
        try:
            is_venv = (candidate / "pyvenv.cfg").is_file()
        except OSError:
            continue
        if is_venv and _within(candidate, root):
            return candidate
    return None


def _site_packages(venv: Path) -> list[Path]:
    found = sorted(venv.glob("lib/python*/site-packages")) + [venv / "Lib" / "site-packages"]
    return [path for path in found if path.is_dir()]


def _read_metadata(path: Path) -> tuple[str, str]:
    with path.open("rb") as handle:
        return _parse_rfc822_name_version(io.BytesIO(handle.read(_MAX_METADATA_BYTES)))


def read_venv(venv: Path, root: Path) -> VenvInventory:
    """Installed distributions of *venv*, skipping anything that escapes *root*."""
    inventory = VenvInventory(venv=venv)
    seen: set[str] = set()
    for site in _site_packages(venv):
        if not _within(site, root):
            continue
        for pattern, filename in _METADATA_FILES:
            for meta_dir in sorted(site.glob(pattern)):
                if len(inventory.distributions) >= MAX_DISTRIBUTIONS:
                    inventory.truncated = True
                    return inventory
                metadata = meta_dir / filename
                if not _within(metadata, root) or not metadata.is_file():
                    continue
                try:
                    name, version = _read_metadata(metadata)
                except OSError as exc:
                    logger.debug("Unreadable installed metadata %s: %s", metadata, exc)
                    continue
                key = canonicalize_name(name) if name else ""
                if key and version and key not in seen:
                    seen.add(key)
                    inventory.distributions.append(InstalledDistribution(name, version, metadata))
    return inventory
