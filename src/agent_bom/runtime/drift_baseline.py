"""Server-scoped local tool baselines; missing identity means no persistence."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from agent_bom.storage import state_home


def baseline_path(server_id: str | None) -> Path | None:
    """Hash the complete caller-scoped identity without storing it on disk."""
    if not server_id or not server_id.strip():
        return None
    digest = hashlib.sha256(server_id.encode("utf-8")).hexdigest()
    return state_home.state_dir() / "drift_baselines" / f"{digest}.json"


def persist_baseline(path: Path | None, tools: set[str]) -> None:
    """Atomically replace this server's baseline; I/O failure stays fail-open."""
    if path is None:
        return
    tmp: Path | None = None
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # A private, unique temporary file prevents concurrent writers from
        # replacing each other's in-flight write. Replacement stays atomic.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, suffix=".tmp", delete=False) as stream:
            tmp = Path(stream.name)
            json.dump(sorted(tools), stream)
        tmp.replace(path)
    except OSError:
        pass
    finally:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


def restore_baseline(path: Path | None) -> set[str] | None:
    """Read a scoped catalog; never infer an owner for legacy global state."""
    if path is not None:
        try:
            tools = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(tools, list) and all(isinstance(tool, str) for tool in tools):
                return set(tools)
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
    return None
