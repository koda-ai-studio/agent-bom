"""Remember the last local scan of each target and say what changed since.

Each target (the scan inputs, hashed) keeps one small JSON summary under
``<state dir>/last-scan/``: finding identities, MCP server and tool ids with
redacted names, the scan time and its outcome. No paths, secrets, versions of
credentials or report bodies are stored; the file is size-bounded, written
atomically with owner-only permissions, and the directory keeps at most
``MAX_TARGETS`` summaries. ``AGENT_BOM_NO_SCAN_MEMORY=1`` disables it.

The comparison is :func:`agent_bom.history.diff_reports`, the same judgement
``agent-bom report diff`` and ``scan --baseline`` use.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from agent_bom.core.settings import env_flag
from agent_bom.core.trend import trend_direction
from agent_bom.history import _get_inventory_snapshot, diff_reports
from agent_bom.security import sanitize_text
from agent_bom.storage import state_home

OPT_OUT_ENV = "AGENT_BOM_NO_SCAN_MEMORY"
SCHEMA = 1
MAX_FINDINGS = 5000
MAX_ENTITIES = 2000
MAX_TARGETS = 200
MAX_FILE_BYTES = 2_000_000


def disabled() -> bool:
    return env_flag(OPT_OUT_ENV)


def summary_dir() -> Path:
    return state_home.state_path("last-scan")


def target_key(parts: Mapping[str, Any]) -> str:
    """Stable hash of the scan inputs; the inputs themselves are never stored."""
    canonical = json.dumps({k: parts[k] for k in sorted(parts) if parts[k] not in (None, "", (), [], False)}, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _entities(snapshot: Mapping[str, Any], kind: str) -> list[dict[str, str]]:
    items = []
    for item in (snapshot.get(kind) or [])[:MAX_ENTITIES]:
        if isinstance(item, Mapping) and item.get("id"):
            items.append({"id": str(item["id"])[:200], "name": sanitize_text(item.get("name") or "", max_len=120)})
    return items


def build_summary(report_json: Mapping[str, Any], *, outcome: str) -> dict[str, Any]:
    findings = [
        {
            "vulnerability_id": str(br.get("vulnerability_id") or ""),
            "package": str(br.get("package") or ""),
            "ecosystem": str(br.get("ecosystem") or ""),
        }
        for br in (report_json.get("blast_radius") or [])[:MAX_FINDINGS]
        if isinstance(br, Mapping) and br.get("vulnerability_id")
    ]
    snapshot = _get_inventory_snapshot(dict(report_json))
    return {
        "schema": SCHEMA,
        "generated_at": str(report_json.get("generated_at") or ""),
        "outcome": outcome,
        "truncated": len(report_json.get("blast_radius") or []) > MAX_FINDINGS,
        "blast_radius": findings,
        "inventory_snapshot": {"servers": _entities(snapshot, "servers"), "tools": _entities(snapshot, "tools")},
    }


def load_summary(key: str) -> dict[str, Any] | None:
    path = summary_dir() / f"{key}.json"
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("schema") == SCHEMA else None


def _prune(directory: Path) -> None:
    summaries = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in summaries[MAX_TARGETS:]:
        stale.unlink(missing_ok=True)


def save_summary(key: str, summary: Mapping[str, Any]) -> None:
    directory = summary_dir()
    directory.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(summary, separators=(",", ":"))
    if len(payload.encode("utf-8")) > MAX_FILE_BYTES:
        return
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.chmod(tmp, 0o600)
        os.replace(tmp, directory / f"{key}.json")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    _prune(directory)


@dataclass(frozen=True)
class ScanChange:
    previous_at: str
    new_findings: int
    resolved_findings: int
    new_servers: int
    new_tools: int
    partial: bool

    @property
    def unchanged(self) -> bool:
        return not (self.new_findings or self.resolved_findings or self.new_servers or self.new_tools)


def compare(previous: Mapping[str, Any], current_summary: Mapping[str, Any]) -> ScanChange:
    diff = diff_reports(dict(previous), dict(current_summary))
    inventory = diff["inventory_diff"]["summary"]
    partial = any(item.get("outcome") != "complete" or item.get("truncated") for item in (previous, current_summary))
    return ScanChange(
        previous_at=str(previous.get("generated_at") or "unknown"),
        new_findings=diff["summary"]["new_findings"],
        resolved_findings=diff["summary"]["resolved_findings"],
        new_servers=inventory.get("new_servers", 0),
        new_tools=inventory.get("new_tools", 0),
        partial=partial,
    )


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def delta_line(change: ScanChange) -> str:
    """One console line (Rich markup) describing the change since the last scan."""
    when = change.previous_at[:16].replace("T", " ")
    if change.unchanged:
        body = "no new or resolved vulnerabilities, no new MCP servers or tools"
    else:
        parts = [
            f"[red]{change.new_findings} new vulnerabilit{'y' if change.new_findings == 1 else 'ies'}[/red]",
            f"[green]{change.resolved_findings} resolved[/green]",
        ]
        if change.new_servers:
            parts.append(f"[yellow]{_plural(change.new_servers, 'new MCP server')}[/yellow]")
        if change.new_tools:
            parts.append(f"[yellow]{_plural(change.new_tools, 'new MCP tool')}[/yellow]")
        body = " · ".join(parts)
    caveat = " [dim](a partial scan on either side can make counts incomplete)[/dim]" if change.partial else ""
    direction = trend_direction(change.new_findings, change.resolved_findings)
    return f"  [bold]Since last scan[/bold] ({when}, {direction}): {body}{caveat}"


def trend_payload(change: ScanChange) -> dict[str, Any]:
    """The change in the shape human report renderers read from ``AIBOMReport.since_last_scan``."""
    return {
        "previous_at": change.previous_at,
        "new": change.new_findings,
        "resolved": change.resolved_findings,
        "new_servers": change.new_servers,
        "new_tools": change.new_tools,
        "partial": change.partial,
        "direction": trend_direction(change.new_findings, change.resolved_findings),
    }


__all__ = [
    "MAX_TARGETS",
    "OPT_OUT_ENV",
    "ScanChange",
    "build_summary",
    "compare",
    "delta_line",
    "disabled",
    "load_summary",
    "save_summary",
    "summary_dir",
    "target_key",
    "trend_payload",
]
