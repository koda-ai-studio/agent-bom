"""Bounded, symlink-refusing reads of well-known files under a scanned root.

Host and VM-snapshot detectors read version markers from fixed paths. A
snapshot is untrusted input: a path component that is a symlink can point the
read at the scanning machine itself, and a crafted file can be arbitrarily
large. Every read here refuses symlinked components, accepts only regular
files, and stops at a byte budget. Nothing is ever executed.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

_CHUNK = 1 << 20


def regular_file(root: Path, rel: str) -> Path | None:
    """``root/rel`` when it is a regular file reached without any symlink."""
    path = root / rel
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return None
        if path.resolve(strict=True) != root.resolve(strict=True).joinpath(rel):
            return None
    except (OSError, RuntimeError):
        return None
    return path


def read_bounded(root: Path, rel: str, limit: int) -> bytes | None:
    """File content, or ``None`` when missing, symlinked, unreadable or over ``limit`` bytes."""
    path = regular_file(root, rel)
    if path is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            content = handle.read(limit + 1)
    except OSError:
        return None
    return content if len(content) <= limit else None


def search_bounded(root: Path, rel: str, pattern: re.Pattern[bytes], budget: int) -> re.Match[bytes] | None:
    """First ``pattern`` match within the first ``budget`` bytes of a file, read in chunks."""
    path = regular_file(root, rel)
    if path is None:
        return None
    overlap = 256
    tail = b""
    consumed = 0
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            while consumed < budget:
                chunk = handle.read(min(_CHUNK, budget - consumed))
                if not chunk:
                    return None
                consumed += len(chunk)
                window = tail + chunk
                match = pattern.search(window)
                if match is not None:
                    return match
                tail = window[-overlap:]
    except OSError:
        return None
    return None


def list_names(root: Path, rel_dir: str, limit: int = 4096) -> list[str]:
    """Entry names directly under ``root/rel_dir`` (not followed through symlinks), capped."""
    directory = root / rel_dir
    try:
        if not stat.S_ISDIR(directory.lstat().st_mode):
            return []
        if directory.resolve(strict=True) != root.resolve(strict=True).joinpath(rel_dir):
            return []
        with os.scandir(directory) as entries:
            names = []
            for entry in entries:
                names.append(entry.name)
                if len(names) >= limit:
                    break
    except (OSError, RuntimeError):
        return []
    return sorted(names)
