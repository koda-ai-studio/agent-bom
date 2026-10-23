"""Decide whether a write outside the session's working directory is a risk signal.

Home dotfiles, credential directories and system paths always stay risky. Writes
into another checkout of the same git repository (worktrees), the OS temp dir or
the agent's own state directory are counted separately as low signal. Git is
asked locally (``rev-parse --git-common-dir``), cached per directory and capped.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

MAX_GIT_LOOKUPS = 256
_GIT_TIMEOUT_SECONDS = 2.0
_SYSTEM_PREFIXES = ("/etc/", "/usr/", "/bin/", "/sbin/", "/System/", "/Library/", "/var/root/", "/opt/homebrew/etc/")
_TEMP_PREFIXES = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
_AGENT_STATE_DIRS = (".claude", ".codex")


def _within(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/")


class WriteScope:
    def __init__(self, *, home: Path | None = None, temp_roots: tuple[str, ...] | None = None) -> None:
        self.home = (home or Path.home()).resolve()
        roots = temp_roots if temp_roots is not None else (tempfile.gettempdir(), *_TEMP_PREFIXES)
        self.temp_roots = tuple(sorted({str(Path(root).resolve()) for root in roots} | set(roots)))
        self._common: dict[str, str | None] = {}
        self._lookups = 0

    def expand(self, path: str) -> str:
        return str(self.home) + path[1:] if path == "~" or path.startswith("~/") else path

    def _sensitive(self, path: str) -> bool:
        if path.startswith(_SYSTEM_PREFIXES):
            return True
        home = str(self.home)
        if not _within(path, home) or path == home:
            return False
        first = path[len(home) + 1 :].split("/", 1)[0]
        return first.startswith(".") and first not in _AGENT_STATE_DIRS

    def _git_common_dir_uncached(self, directory: str) -> str | None:
        if self._lookups >= MAX_GIT_LOOKUPS:
            return None
        self._lookups += 1
        try:
            result = subprocess.run(
                ["git", "-C", directory, "rev-parse", "--path-format=absolute", "--git-common-dir"],
                capture_output=True,
                text=True,
                timeout=_GIT_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        text = result.stdout.strip()
        return str(Path(text).resolve()) if result.returncode == 0 and text else None

    def git_common_dir(self, path: str) -> str | None:
        current = Path(path)
        while not current.exists() and current != current.parent:
            current = current.parent
        directory = str(current if current.is_dir() else current.parent)
        if directory not in self._common:
            self._common[directory] = self._git_common_dir_uncached(directory)
        return self._common[directory]

    def classify(self, path: str, root: str) -> tuple[str, str]:
        """``("risky", severity)`` or ``("low_signal", reason)`` for a write outside ``root``."""
        target, cwd = self.expand(path), self.expand(root)
        if self._sensitive(target):
            return "risky", "high"
        if any(_within(target, str(self.home / name)) for name in _AGENT_STATE_DIRS):
            return "low_signal", "agent_state"
        target_repo = self.git_common_dir(target)
        if target_repo is not None:
            same = cwd and target_repo == self.git_common_dir(cwd)
            return ("low_signal", "same_repository") if same else ("risky", "medium")
        if any(_within(target, root) for root in self.temp_roots):
            return "low_signal", "temp_dir"
        return "risky", "medium"
