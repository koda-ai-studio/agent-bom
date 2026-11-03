"""Bounded semantic annotations over the canonical same-scope graph diff."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from agent_bom.graph.diff_view import edge_parts
from agent_bom.graph.repository_identity import repository_scope

_KINDS = {"workspace_package": "workspace_packages", "dbt_model": "dbt_models", "gitlab_job": "pipelines", "airflow_dag": "pipelines"}
_FILE_WINDOW = 500


def compact_repository_context(result: Any) -> dict | None:
    inventory = result.get("project_inventory") if isinstance(result, Mapping) else None
    if not isinstance(inventory, Mapping) or not repository_scope(inventory):
        return None
    context = inventory["repository_context"]
    fields = {key: context.get(key) for key in ("version", "scope_id", "ref", "revision", "ref_status", "status", "coverage")}
    for adapter in ("code", "pipelines", "dbt"):
        value = context.get(adapter)
        if isinstance(value, Mapping):
            fields[adapter] = {key: value.get(key) for key in ("status", "coverage", "schema")}
    return fields


def repository_basis(result: Any) -> dict | None:
    context = compact_repository_context(result)
    if context is None:
        return None
    coverage = context.get("coverage")
    coverage = (
        {key: value for key, value in coverage.items() if isinstance(key, str) and isinstance(value, str)}
        if isinstance(coverage, dict)
        else {}
    )
    for adapter in ("code", "pipelines", "dbt"):
        row = context.get(adapter, {})
        coverage[adapter] = str(row.get("coverage") or row.get("schema") or "not_recorded")[:200]
    return {
        **{key: context.get(key) for key in ("scope_id", "ref", "revision", "ref_status", "status")},
        "coverage_key": hashlib.sha256(json.dumps(coverage, sort_keys=True).encode()).hexdigest(),
    }


def comparison_reason(old: Any, new: Any, collection: dict) -> str | None:
    if not old or not new:
        return "repository_basis_unavailable"
    if collection.get("status") != "comparable" or old.get("status") != "complete" or new.get("status") != "complete":
        return "incomplete_repository_collection"
    if old.get("scope_id") != new.get("scope_id") or old.get("ref") != new.get("ref"):
        return "different_repository_or_ref"
    if any(
        row.get("ref_status") != "recorded"
        or row.get("ref") == "unrecorded"
        or not isinstance(row.get("revision"), str)
        or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", row["revision"])
        for row in (old, new)
    ):
        return "repository_ref_unavailable"
    if old.get("coverage_key") != new.get("coverage_key"):
        return "different_repository_coverage"
    return None


def _finding_files(store: Any, tenant: str, new_id: str, scope: str, diff: dict) -> dict:
    candidates: list[tuple[str, str]] = []
    truncated = False
    for entry in diff.get("edges_added", []):
        source, target, relation, _, _ = edge_parts(entry)
        if relation == "affects":
            if len(candidates) >= _FILE_WINDOW:
                truncated = True
                break
            candidates.append((source, target))
    ids = {node_id for pair in candidates for node_id in pair}
    nodes = {}
    ordered = sorted(ids)
    for start in range(0, len(ordered), 100):
        nodes.update(
            {node.id: node for node in store.nodes_by_ids(tenant_id=tenant, scan_id=new_id, node_ids=set(ordered[start : start + 100]))}
        )
    files = {}
    for source, target in candidates:
        a, b = nodes.get(source), nodes.get(target)
        if (
            a is not None
            and b is not None
            and a.entity_type.value in {"vulnerability", "misconfiguration"}
            and (b.entity_type.value in {"source_file", "config_file"} and b.attributes.get("repository_scope") == scope)
        ):
            files[b.id] = {"id": b.id, "label": b.label, "scan_id": new_id}
    return {"count": len(files), "status": "partial" if truncated else "complete", "rows": [files[key] for key in sorted(files)[:10]]}


def repository_change_summary(store: Any, tenant: str, old_id: str, new_id: str, old: Any, new: Any, collection: dict) -> dict:
    from agent_bom.api.graph_diff_read import _compute_rows, _rows_cache_key

    reason = comparison_reason(old, new, collection)
    if reason:
        return {"status": "unavailable", "reason": reason}
    generation = _rows_cache_key(store, tenant, old_id, new_id)
    if generation is None:
        return {"status": "unavailable", "reason": "snapshot_generation_unavailable"}
    diff, _ = _compute_rows(store, tenant, old_id, new_id)
    counts = {kind: {"added": 0, "removed": 0} for kind in sorted(set(_KINDS.values()))}
    rows: list[dict[str, Any]] = []
    for change, snapshot in (("added", new_id), ("removed", old_id)):
        for node in diff.get(f"nodes_{change}", []):
            attrs = node.get("attributes", {}) if isinstance(node, dict) else {}
            subtype = attrs.get("subtype")
            kind = _KINDS.get(subtype) if isinstance(subtype, str) else None
            if kind and attrs.get("repository_scope") == new["scope_id"]:
                counts[kind][change] += 1
                if len(rows) < 30:
                    rows.append(
                        {"id": node["id"], "label": node.get("label", node["id"]), "kind": kind, "change": change, "scan_id": snapshot}
                    )
    files = _finding_files(store, tenant, new_id, new["scope_id"], diff)
    if generation != _rows_cache_key(store, tenant, old_id, new_id):
        return {"status": "unavailable", "reason": "snapshot_generation_changed"}
    return {
        "status": files["status"],
        "counts": counts,
        "rows": rows,
        "files_with_new_findings": files,
        "old_scan_id": old_id,
        "new_scan_id": new_id,
        "ref": new["ref"],
        "scope_id": new["scope_id"],
        "rows_truncated": sum(sum(values.values()) for values in counts.values()) > len(rows),
    }
