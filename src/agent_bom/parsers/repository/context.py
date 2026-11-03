"""Collect optional repository metadata using one shared artifact budget."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_bom.parsers.repository.artifacts import RepositoryReader
from agent_bom.parsers.repository.dbt import dbt_context
from agent_bom.parsers.repository.pipelines import pipeline_context
from agent_bom.parsers.repository.ref import repository_ref
from agent_bom.parsers.repository.workspaces import workspace_context


def collect_repository_context(root: Path) -> dict[str, Any]:
    reader = RepositoryReader(root)
    ref = repository_ref(reader)
    context = workspace_context(reader)
    context.update(ref)
    dbt = dbt_context(reader)
    if dbt is not None:
        context["dbt"] = dbt
    context["pipelines"], context["code"] = pipeline_context(reader, context["workspace_packages"])
    if ref != repository_ref(reader):
        reader.note(".git/HEAD", "ref_changed_during_collection")
        context["ref_status"] = "changed_during_collection"
    if reader.unresolved or (dbt is not None and dbt["status"] != "complete"):
        context["status"] = "partial"
    return context
