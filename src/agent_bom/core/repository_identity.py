"""Pure, versioned repository identity and relative-path validation."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath


def relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or ":" in value:
        return None
    return path.as_posix()


def repository_id(scope: str, kind: str, key: str) -> str:
    """Versioned, repository-scoped identities; tenant isolation stays server-owned."""
    digest = hashlib.sha256(f"v1\0{scope}\0{kind}\0{key}".encode()).hexdigest()
    return f"repo:{kind}:{digest}"
