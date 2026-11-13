"""Keep the local vulnerability DB from crossing tests.

The default DB resolves to ``<state dir>/db/vulns.db`` (or ``~/.agent-bom/db``),
and conftest pins one state dir and one HOME per worker process. A test that
writes the default DB without its own path would otherwise leave stale
advisories that make every later ``check`` on that worker report incomplete.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

# conftest exports the per-worker HOME and state dir before this plugin loads.
_SHARED_DB_DIRS = (
    Path(os.environ["AGENT_BOM_STATE_DIR"]).resolve() / "db",
    Path(os.environ["HOME"]).resolve() / ".agent-bom" / "db",
)


def shared_vuln_db_dirs() -> tuple[Path, ...]:
    """The default vuln DB directories every test on this worker would share."""
    return _SHARED_DB_DIRS


def point_default_vuln_db(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """Point ``schema.DB_PATH`` and every module-level copy of it at *path*.

    Some modules bind ``DB_PATH`` at import (``from agent_bom.db.schema import
    DB_PATH``), so patching the schema module alone leaves them on the old file.
    """
    from agent_bom.db import schema

    original = schema.DB_PATH
    for name, module in list(sys.modules.items()):
        if (name == "agent_bom" or name.startswith("agent_bom.")) and getattr(module, "DB_PATH", None) is original:
            monkeypatch.setattr(module, "DB_PATH", path)


@pytest.fixture(autouse=True)
def _remove_shared_vuln_db() -> Iterator[None]:
    """Delete the worker's shared default vuln DB directories after every test.

    Tests that need a DB pass their own path or point ``DB_PATH`` at
    ``tmp_path``; those are untouched. Runs last on teardown because plugin
    autouse fixtures are set up before any conftest or module fixture.
    """
    yield
    for directory in _SHARED_DB_DIRS:
        shutil.rmtree(directory, ignore_errors=True)
