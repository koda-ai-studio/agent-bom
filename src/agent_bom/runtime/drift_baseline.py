"""Server-scoped local tool baselines; missing identity means no persistence."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from agent_bom.security import sanitize_text
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


MAX_TOOL_DEFINITIONS = 4096
ToolFingerprints = dict[str, dict[str, str]]


def fingerprint_tools(tools: list[dict]) -> ToolFingerprints | None:
    """Hash bounded declaration fields; invalid or oversized catalogs stay incomplete."""
    fingerprints: ToolFingerprints = {}
    if len(tools) > MAX_TOOL_DEFINITIONS:
        return None
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not 0 < len(tool["name"]) <= 512:
            return None
        if tool["name"] in fingerprints:
            return None
        if "description" in tool and not isinstance(tool["description"], str):
            return None
        if "inputSchema" in tool and not isinstance(tool["inputSchema"], dict):
            return None
        try:
            fields = {
                key: json.dumps(tool.get(key), sort_keys=True, ensure_ascii=True, allow_nan=False)
                for key in ("name", "description", "inputSchema")
            }
        except (ValueError, TypeError, RecursionError):
            return None
        if sum(len(value) for value in fields.values()) > 262144:
            return None
        fingerprints[tool["name"]] = {key: hashlib.sha256(value.encode()).hexdigest() for key, value in fields.items()}
    return fingerprints


def changed_definition_fields(baseline: ToolFingerprints, current: ToolFingerprints) -> list[dict]:
    """Report field names only, never values or their fingerprints."""
    return [
        {"name": sanitize_text(name), "fields": sorted(key for key in fields if fields[key] != baseline[name].get(key))}
        for name, fields in current.items()
        if name in baseline and fields != baseline[name]
    ]


def definition_drift_details(baseline: ToolFingerprints, current: ToolFingerprints) -> list[dict]:
    """Include existing tier-A fields so audit redaction preserves the change kind."""
    details = []
    for change in changed_definition_fields(baseline, current):
        reason = {
            ("description",): "tool_description_changed",
            ("inputSchema",): "tool_schema_changed",
        }.get(tuple(change["fields"]), "tool_definition_changed")
        details.append({"tool_name": change["name"], "reason_code": reason, "changed_tools": [change]})
    return details
