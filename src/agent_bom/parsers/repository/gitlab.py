"""Literal GitLab jobs/local includes; no shell execution, expansion or remote fetches."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from agent_bom.core.repository_identity import relative_path
from agent_bom.parsers.repository.artifacts import RepositoryReader
from agent_bom.parsers.repository.python_source import literal
from agent_bom.parsers.repository.workspaces import _yaml

_RESERVED = {"include", "stages", "variables", "workflow", "default", "image", "services", "before_script", "after_script", "cache", "spec"}


def _includes(value: Any, path: str, reader: RepositoryReader) -> list[str]:
    raw = value if isinstance(value, list) else [value] if value else []
    if len(raw) > 32:
        reader.note(path, "include_limit")
    result = []
    for row in raw[:32]:
        value = row.get("local") if isinstance(row, dict) and set(row) == {"local"} else row if isinstance(row, str) else None
        # GitLab leading / means repository-root-relative, never a filesystem root.
        clean = relative_path(value.lstrip("/")) if isinstance(value, str) else None
        if clean is None or not clean.endswith((".yml", ".yaml")) or any(char in clean for char in "$*?[]"):
            reader.note(path, "include_unresolved")
        else:
            result.append(clean)
    return result


def _jobs(reader: RepositoryReader) -> dict[str, tuple[dict, str, str]]:
    jobs: dict[str, tuple[dict, str, str]] = {}
    visited: set[str] = set()

    def visit(path: str, chain: tuple[str, ...]) -> None:
        if path in chain or len(chain) >= 8 or len(visited) >= 32:
            reader.note(path, "include_cycle_or_limit")
            return
        if path in visited:
            return
        visited.add(path)
        text = reader.read(path, max_bytes=256 * 1024)
        if text is None:
            if chain:
                reader.note(path, "include_unavailable")
            return
        try:
            data = _yaml(text)
        except (ValueError, RecursionError):
            reader.note(path, "pipeline_yaml_invalid")
            return
        if not isinstance(data, dict):
            reader.note(path, "pipeline_yaml_invalid")
            return
        for child in _includes(data.get("include"), path, reader):
            visit(child, (*chain, path))
        if len(data) > 1000:
            reader.note(path, "pipeline_job_limit")
        for name, row in list(data.items())[:1000]:
            if not literal(name) or name.startswith(".") or name in _RESERVED or not isinstance(row, dict):
                continue
            if name in jobs:
                # GitLab deep merges keys; keep this declaration but do not claim a fully resolved job.
                reader.note(path, "job_override_unresolved")
            jobs[name] = (row, path, hashlib.sha256(text.encode()).hexdigest())
            if len(jobs) >= 1000:
                reader.note(path, "pipeline_job_limit")
                return

    visit(".gitlab-ci.yml", ())
    return jobs


def gitlab_context(reader: RepositoryReader) -> tuple[list[dict], list[dict]]:
    jobs = _jobs(reader)
    nodes, edges = [], []
    for name, (row, path, digest) in sorted(jobs.items()):
        key = f"gitlab:{name}"
        if "extends" in row:
            reader.note(path, "job_inheritance_unresolved")
        environment = row.get("environment")
        target = literal(environment.get("name") if isinstance(environment, dict) else environment)
        if environment and target is None:
            reader.note(path, "deployment_target_unresolved")
        raw_secrets = row.get("secrets")
        secrets = (
            sorted(k for k in raw_secrets if isinstance(k, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", k))[:100]
            if isinstance(raw_secrets, dict)
            else []
        )
        nodes.append(
            {
                "key": key,
                "kind": "gitlab_job",
                "name": name,
                "path": path,
                "digest": digest,
                "deployment_target": target,
                "secret_references": secrets,
            }
        )
        needs = row.get("needs", [])
        if not isinstance(needs, list):
            reader.note(path, "needs_unresolved")
            continue
        if len(needs) > 100:
            reader.note(path, "needs_limit")
        for need in needs[:100]:
            dependency = need.get("job") if isinstance(need, dict) and not ({"project", "pipeline"} & need.keys()) else need
            if isinstance(dependency, str) and dependency in jobs:
                edges.append({"source": key, "target": f"gitlab:{dependency}", "path": path, "basis": "declared_needs"})
            else:
                reader.note(path, "needs_unresolved")
    return nodes, edges
