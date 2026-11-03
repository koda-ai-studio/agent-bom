"""Bounded manifest v8–v12 lineage. Reads local artifacts, never dbt/Jinja/SQL execution."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.core.repository_identity import relative_path
from agent_bom.parsers.repository.artifacts import RepositoryReader
from agent_bom.parsers.repository.workspaces import _yaml

MAX_NODES = 2000
MAX_EDGES = 10_000
_ARTIFACT = "target/manifest.json"
_KINDS = {"model", "source", "seed", "exposure"}


def _text(value: Any, limit: int = 512) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= limit and all(ord(c) >= 32 for c in value) else None


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _local_account(reader: RepositoryReader) -> str | None:
    project = reader.read("dbt_project.yml") or reader.read("dbt_project.yaml")
    profiles = reader.read("profiles.yml") or reader.read("profiles.yaml")
    try:
        profile_name = _mapping(_yaml(project or "")).get("profile")
        if not isinstance(profile_name, str):
            return None
        profile = _mapping(_mapping(_yaml(profiles or "")).get(profile_name))
        target_name = profile.get("target")
        if not isinstance(target_name, str):
            return None
        target = _mapping(_mapping(profile.get("outputs")).get(target_name))
        account = target.get("account")
        if target.get("type") == "snowflake" and isinstance(account, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", account):
            return account
    except (ValueError, RecursionError):
        reader.note("profiles.yml", "invalid_or_unreadable_artifact")
    return None


def _freshness(metadata: dict[str, Any]) -> str:
    stamp = metadata.get("generated_at")
    try:
        generated = datetime.fromisoformat(stamp.replace("Z", "+00:00")) if isinstance(stamp, str) else None
        if generated is None or generated.tzinfo is None:
            return "unknown"
        age = datetime.now(timezone.utc) - generated
        if age < -timedelta(minutes=5):
            return "unknown"
        return "stale" if age > timedelta(days=7) else "current"
    except ValueError:
        return "unknown"


def _nodes(data: dict[str, Any], note: Any) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    nodes: dict[str, dict[str, Any]] = {}
    parents: dict[str, list[str]] = {}
    visited = 0
    for section in ("nodes", "sources", "exposures"):
        if not isinstance(data.get(section), dict):
            note(section, "invalid_manifest_section")
        rows = _mapping(data.get(section))
        for key in sorted(rows):
            row = _mapping(rows[key])
            kind = row.get("resource_type")
            if not isinstance(kind, str):
                note(_ARTIFACT, "invalid_node_kind")
                continue
            if kind not in _KINDS:
                continue
            visited += 1
            if visited > MAX_NODES:
                note(_ARTIFACT, "node_limit")
                return list(nodes.values()), parents
            uid, name = _text(row.get("unique_id")), _text(row.get("name"), 256)
            if not uid or key != uid or not uid.startswith(f"{kind}.") or not name:
                note(_ARTIFACT, "invalid_node_identity")
                continue
            if uid in nodes:
                note(uid, "duplicate_node_identity")
                continue
            path = relative_path(row.get("original_file_path"))
            if path is None:
                note(uid, "invalid_source_path")
            nodes[uid] = {"key": uid, "kind": kind, "name": name, "path": path, "relation_name": _text(row.get("relation_name"), 1024)}
            raw_parents = _mapping(row.get("depends_on")).get("nodes", [])
            if not isinstance(raw_parents, list):
                note(uid, "invalid_parent_list")
                raw_parents = []
            if len(raw_parents) > 256:
                note(uid, "parent_limit")
            if any(_text(p) is None for p in raw_parents[:256]):
                note(uid, "invalid_parent")
            parents[uid] = sorted({p for p in raw_parents[:256] if _text(p) is not None})
    return list(nodes.values()), parents


def _edges(nodes: list[dict[str, Any]], parents: dict[str, list[str]], note: Any) -> list[dict[str, str]]:
    ids = {n["key"] for n in nodes}
    edges: list[dict[str, str]] = []
    children: dict[str, list[str]] = {key: [] for key in ids}
    indegrees = Counter({key: 0 for key in ids})
    for source in sorted(parents):
        for target in parents[source]:
            if target not in ids:
                note(target, "missing_parent")
                continue
            if len(edges) >= MAX_EDGES:
                note(_ARTIFACT, "edge_limit")
                return edges
            edges.append({"source": source, "target": target})
            children[target].append(source)
            indegrees[source] += 1
    queue = deque(key for key, degree in indegrees.items() if degree == 0)
    removed = 0
    while queue:
        key = queue.popleft()
        removed += 1
        for child in children[key]:
            indegrees[child] -= 1
            if indegrees[child] == 0:
                queue.append(child)
    if removed < len(ids):
        note(_ARTIFACT, "cycle")
    return edges


def dbt_context(reader: RepositoryReader) -> dict[str, Any] | None:
    """Return only allowlisted artifact metadata; credential values and SQL are omitted."""
    text = reader.read(_ARTIFACT, max_bytes=16 * 1024 * 1024)
    if text is None and not any((reader.root / name).is_file() for name in ("dbt_project.yml", "dbt_project.yaml", _ARTIFACT)):
        return None
    reasons: list[dict[str, str]] = []
    counts: Counter[str] = Counter()

    def note(artifact: str, reason: str) -> None:
        counts[reason] += 1
        if len(reasons) < 100:
            reasons.append({"artifact": artifact, "reason": reason})

    result: dict[str, Any] = {
        "artifact": _ARTIFACT,
        "digest": hashlib.sha256(text.encode()).hexdigest() if text else None,
        "status": "unavailable",
        "freshness": "unknown",
        "nodes": [],
        "edges": [],
        "snowflake_account": None,
        "unresolved": reasons,
        "unresolved_counts": counts,
    }
    try:
        data = json.loads(text or "")
    except (ValueError, RecursionError):
        note(_ARTIFACT, "manifest_missing_or_invalid")
        return result
    if not isinstance(data, dict):
        note(_ARTIFACT, "invalid_manifest")
        return result
    metadata = _mapping(data.get("metadata"))
    schema = metadata.get("dbt_schema_version")
    if not isinstance(schema, str) or not re.fullmatch(r"https://schemas\.getdbt\.com/dbt/manifest/v(?:8|9|10|11|12)\.json", schema):
        note(_ARTIFACT, "unsupported_manifest_version")
        return result
    result.update(schema=schema, generated_at=_text(metadata.get("generated_at")), adapter=_text(metadata.get("adapter_type")))
    result["freshness"] = _freshness(metadata)
    nodes, parents = _nodes(data, note)
    result["nodes"], result["edges"] = nodes, _edges(nodes, parents, note)
    if result["adapter"] == "snowflake":
        result["snowflake_account"] = _local_account(reader)
        if not result["snowflake_account"]:
            note("profiles.yml", "account_unresolved")
    result["status"] = "partial" if counts or result["freshness"] != "current" else "complete"
    return result
