"""Which project a scan covered, and the finding identity that keeps projects apart.

The same package version in two projects is two findings, each with its own
dates and resolution. The project comes from what a scan already records: a
pushed report's opaque ``target_scope``, or an API scan's target fields. A scan
with neither keeps the reported identity. The derived id is a one-way hash, so
the scope never appears in it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agent_bom.canonical_ids import canonical_id
from agent_bom.evidence.push_scope import valid_target_scope

REPORT_ID_FIELD = "report_canonical_id"
_REQUEST_TARGETS = (
    "repo_url",
    "agent_projects",
    "filesystem_paths",
    "images",
    "tf_dirs",
    "gha_path",
    "jupyter_dirs",
    "k8s_namespace",
    "sbom",
    "inventory",
    "external_scan",
)


def finding_project_key(job: Any) -> str | None:
    raw_result = getattr(job, "result", None)
    result = raw_result if isinstance(raw_result, dict) else {}
    if result.get("pushed"):
        scope = result.get("target_scope")
        return scope if valid_target_scope(scope) else None
    request = getattr(job, "request", None)
    dump = getattr(request, "model_dump", None)
    fields = dump(mode="json") if callable(dump) else request if isinstance(request, dict) else {}
    targets = {name: fields[name] for name in _REQUEST_TARGETS if fields.get(name)}
    explicit = getattr(job, "target", None)
    if isinstance(explicit, dict) and explicit:
        targets["job_target"] = explicit
    if not targets:
        return None
    return "request:" + hashlib.sha256(json.dumps(targets, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _project_id(project: str, identity: str) -> str:
    return canonical_id("finding-project", project, identity)


def with_project_identity(row: dict[str, Any], project: str | None) -> dict[str, Any]:
    """The row under its project's identity; the reported id stays for joins to the graph and hub."""
    if project is None or row.get(REPORT_ID_FIELD):
        return row
    reported, raw_id = row.get("canonical_id"), row.get("id")
    if not reported and not raw_id:
        return row
    qualified = dict(row)
    qualified[REPORT_ID_FIELD] = str(reported or raw_id)
    if reported:
        qualified["canonical_id"] = _project_id(project, str(reported))
    if raw_id:
        qualified["id"] = _project_id(project, str(raw_id))
    return qualified


def project_finding_id(job: Any, reported_id: str) -> str:
    """The id a reported finding has once the job's project is part of it."""
    project = finding_project_key(job)
    return reported_id if project is None else _project_id(project, reported_id)


def rows_with_project_identity(rows: list[dict[str, Any]], job: Any) -> list[dict[str, Any]]:
    project = finding_project_key(job)
    return rows if project is None else [with_project_identity(row, project) for row in rows]
