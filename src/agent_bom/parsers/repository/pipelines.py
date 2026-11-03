"""Compose bounded local pipeline declarations under repository context."""

from __future__ import annotations

from collections import deque

from agent_bom.parsers.repository.airflow import airflow_context
from agent_bom.parsers.repository.artifacts import RepositoryReader
from agent_bom.parsers.repository.gitlab import gitlab_context
from agent_bom.parsers.repository.python_source import source_trees
from agent_bom.parsers.repository.sdk import sdk_context


def _cycle(nodes: list[dict], edges: list[dict]) -> bool:
    indegree = {row["key"]: 0 for row in nodes}
    children: dict[str, list[str]] = {key: [] for key in indegree}
    for edge in edges:
        indegree[edge["source"]] += 1
        children[edge["target"]].append(edge["source"])
    queue = deque(key for key, degree in indegree.items() if degree == 0)
    visited = 0
    while queue:
        key = queue.popleft()
        visited += 1
        for child in children[key]:
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    return visited < len(indegree)


def pipeline_context(reader: RepositoryReader, packages: list[dict]) -> tuple[dict, dict]:
    nodes, edges = gitlab_context(reader)
    paths = reader.source_files()
    files = set(paths)
    code = []
    for path, digest, tree in source_trees(reader, paths):
        source = sdk_context(reader, path, digest, tree, files, packages)
        if source:
            code.append(source)
        more, links = airflow_context(reader, path, digest, tree)
        if len(nodes) + len(more) > 2000 or len(edges) + len(links) > 10_000:
            reader.note(path, "pipeline_total_limit")
            break
        nodes.extend(more)
        edges.extend(links)
    if _cycle(nodes, edges):
        reader.note(".", "pipeline_dependency_cycle")
    # The shared read/enumeration budget applies to every adapter. Preserve
    # partial status even when the bounded reason list was already full.
    unresolved = list(reader.unresolved)
    pipelines = {
        "status": "partial" if unresolved else "complete",
        "nodes": nodes,
        "edges": edges,
        "unresolved": unresolved,
        "coverage": "literal_gitlab_jobs_and_airflow_dag_operators",
    }
    return pipelines, {
        "status": "partial" if unresolved else "complete",
        "files": code,
        "unresolved": unresolved,
        "coverage": "python_named_sdk_imports_and_static_calls",
    }
