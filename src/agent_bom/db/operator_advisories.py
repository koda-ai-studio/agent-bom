"""Local (workstation/CI) store for operator-declared advisories.

The control plane keeps tenant-scoped advisories in its API store; the CLI and
the local MCP server share this single JSON file under the agent-bom state dir
and match against saved scan history, never by rescanning.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from agent_bom.history import latest_report, load_report_or_sbom
from agent_bom.scanners.operator_advisory import AdvisoryMatchResult, OperatorAdvisory, match_advisories_against_reports
from agent_bom.storage import state_home

_FILENAME = "operator_advisories.json"


def store_path() -> Path:
    return state_home.state_path(_FILENAME)


def load_local_advisories() -> list[OperatorAdvisory]:
    path = store_path()
    if not path.exists():
        return []
    rows = json.loads(path.read_text())
    return [OperatorAdvisory.model_validate(row) for row in rows if isinstance(row, dict)]


def _write(advisories: list[OperatorAdvisory]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps([a.model_dump(mode="json") for a in sorted(advisories, key=lambda a: a.id)], indent=2)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".operator_advisories.")
    with os.fdopen(fd, "w") as handle:
        handle.write(payload)
    os.replace(tmp, path)


def save_local_advisory(advisory: OperatorAdvisory) -> None:
    _write([a for a in load_local_advisories() if a.id != advisory.id] + [advisory])


def remove_local_advisory(advisory_id: str) -> bool:
    current = load_local_advisories()
    kept = [a for a in current if a.id != advisory_id]
    if len(kept) == len(current):
        return False
    _write(kept)
    return True


def local_advisory(advisory_id: str) -> OperatorAdvisory | None:
    wanted = advisory_id.strip().upper()
    return next((a for a in load_local_advisories() if wanted in {i.upper() for i in a.identifiers}), None)


def match_local(advisories: list[OperatorAdvisory], report_paths: list[Path] | None = None) -> AdvisoryMatchResult:
    """Match against explicit reports, else the most recent saved scan in local history."""
    paths = list(report_paths or [])
    if not paths:
        latest = latest_report()
        paths = [latest] if latest is not None else []
    reports: list[dict[str, Any]] = [load_report_or_sbom(path) for path in paths]
    return match_advisories_against_reports(advisories, reports)
