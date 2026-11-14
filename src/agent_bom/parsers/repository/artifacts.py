"""Shared bounds and path validation for optional local repository enrichment."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path, PurePosixPath

from agent_bom.core.repository_identity import relative_path

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 10_000
_SKIP = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".codex", ".claude", ".next", "dist", "build", "target"}


@contextmanager
def _descriptor(path: str | Path, flags: int, *, dir_fd: int | None = None) -> Iterator[int]:
    """Keep one owner for each descriptor, including failed stream wrapping."""
    descriptor = os.open(path, flags, dir_fd=dir_fd)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


class RepositoryReader:
    """Reads only regular local files, with component-wise symlink rejection."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.scope = hashlib.sha256(f"local-root-v1\0{self.root}".encode()).hexdigest()
        self.bytes_read = 0
        self.unresolved: list[dict[str, str]] = []

    def note(self, artifact: str, reason: str) -> None:
        row = {"artifact": artifact[:512], "reason": reason}
        if row not in self.unresolved and len(self.unresolved) < 100:
            self.unresolved.append(row)

    def read(self, relative: str, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> str | None:
        clean = relative_path(relative)
        if clean is None or clean == ".":
            self.note("<invalid path>", "invalid_workspace_path")
            return None
        path = self.root / clean
        if not path.exists() and not path.is_symlink():
            return None
        if self.bytes_read >= MAX_TOTAL_BYTES:
            self.note(clean, "total_byte_limit")
            return None
        try:
            if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
                with ExitStack() as opened:
                    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    descriptor = opened.enter_context(_descriptor(self.root, directory_flags))
                    parts = PurePosixPath(clean).parts
                    for part in parts[:-1]:
                        descriptor = opened.enter_context(_descriptor(part, directory_flags, dir_fd=descriptor))
                    descriptor = opened.enter_context(
                        _descriptor(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                    )
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise ValueError("not a regular file")
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        data = stream.read(min(max_bytes, MAX_TOTAL_BYTES - self.bytes_read) + 1)
            else:
                # Platforms without dir_fd still reject every symlink component.
                if any(p.is_symlink() for p in [path, *path.parents] if p != self.root and p.is_relative_to(self.root)):
                    raise ValueError("symlink")
                if not path.is_file() or not path.resolve().is_relative_to(self.root):
                    raise ValueError("outside root")
                with path.open("rb") as stream:
                    data = stream.read(min(max_bytes, MAX_TOTAL_BYTES - self.bytes_read) + 1)
            limit = min(max_bytes, MAX_TOTAL_BYTES - self.bytes_read)
            self.bytes_read += len(data)
            if len(data) > limit:
                raise ValueError("artifact limit")
            return data.decode("utf-8")
        except (OSError, ValueError):
            self.note(clean, "invalid_or_unreadable_artifact")
            return None

    def directories(self) -> list[str]:
        """Bound enumeration itself, not just the number of matched workspaces."""
        pending = [self.root]
        found = ["."]
        visited = 0
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > MAX_ENTRIES:
                            self.note(".", "entry_limit")
                            return sorted(found)
                        if entry.name in _SKIP or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                            continue
                        path = Path(entry.path)
                        rel = path.relative_to(self.root).as_posix()
                        if len(path.relative_to(self.root).parts) > 12:
                            self.note(rel, "depth_limit")
                            continue
                        found.append(rel)
                        pending.append(path)
            except OSError:
                self.note(directory.relative_to(self.root).as_posix(), "directory_unreadable")
        return sorted(found)

    def source_files(self, suffix: str = ".py", limit: int = 250) -> list[str]:
        """Bound local source enumeration; reads still use component-wise no-follow."""
        pending = [self.root]
        found: list[str] = []
        visited = 0
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > MAX_ENTRIES or len(found) >= limit:
                            self.note(".", "source_enumeration_limit")
                            return sorted(found)
                        if entry.name in _SKIP or entry.name.startswith(".tmp") or entry.is_symlink():
                            continue
                        path = Path(entry.path)
                        relative = path.relative_to(self.root)
                        if entry.is_dir(follow_symlinks=False):
                            if len(relative.parts) <= 12:
                                pending.append(path)
                            else:
                                self.note(relative.as_posix(), "depth_limit")
                        elif entry.is_file(follow_symlinks=False) and entry.name.endswith(suffix):
                            found.append(relative.as_posix())
            except OSError:
                self.note(directory.relative_to(self.root).as_posix(), "directory_unreadable")
        return sorted(found)
