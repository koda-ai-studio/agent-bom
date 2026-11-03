"""Project-owned packages and exact file/dependency membership; no inferred resolution."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from agent_bom.core.repository_identity import relative_path, repository_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.repository_identity import repository_scope, scoped_node_id
from agent_bom.graph.types import EntityType, RelationshipType

_SOURCE = "workspace-manifest"


def _records(inventory: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    context = inventory.get("repository_context", {})
    raw = context.get("workspace_packages", []) if isinstance(context, dict) else []
    records: dict[str, dict[str, Any]] = {}
    for row in raw[:500] if isinstance(raw, list) else []:
        if not isinstance(row, dict) or relative_path(row.get("path")) is None:
            continue
        name, eco, path = row.get("name"), row.get("ecosystem"), row["path"]
        if not isinstance(name, str) or not name or len(name) > 256 or eco not in {"npm", "pypi", "cargo", "go"}:
            continue
        node_id = repository_id(scope, "workspace_package", f"{eco}:{path}:{name}")
        records[node_id] = {**row, "id": node_id}
    return sorted(records.values(), key=lambda r: r["id"])


def apply_workspace_overlay(graph: UnifiedGraph, report: dict[str, Any], now: datetime) -> None:
    inventory = report.get("project_inventory")
    scope = repository_scope(inventory)
    if not scope or not isinstance(inventory, dict):
        return
    records = _records(inventory, scope)
    by_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in records:
        by_name[(row["ecosystem"], row["name"])].append(row["id"])
        node = UnifiedNode(
            id=row["id"],
            entity_type=EntityType.CODE_MODULE,
            label=row["name"],
            attributes={
                "subtype": "workspace_package",
                "first_party": True,
                "repository_scope": scope,
                **{
                    key: row[key]
                    for key in ("path", "ecosystem", "manifest", "manifest_digest", "owners", "owner_source", "evidence_tier")
                    if key in row
                },
            },
            data_sources=[_SOURCE],
            dimensions=NodeDimensions(surface="code"),
            first_seen=now.isoformat(),
            last_seen=now.isoformat(),
        )
        graph.add_node(node)
        directory = scoped_node_id("directory", "" if row["path"] == "." else row["path"], scope)
        if directory not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=directory,
                    entity_type=EntityType.DIRECTORY,
                    label=row["path"],
                    attributes={"path": row["path"], "repository_scope": scope},
                    data_sources=[_SOURCE],
                    dimensions=NodeDimensions(surface="code"),
                )
            )
            root = scoped_node_id("directory", ".", scope)
            if root in graph.nodes and root != directory:
                graph.add_edge(
                    UnifiedEdge(
                        source=root,
                        target=directory,
                        relationship=RelationshipType.CONTAINS,
                        evidence={"tier": "static_scan", "source": _SOURCE},
                    )
                )
        graph.add_edge(
            UnifiedEdge(
                source=directory,
                target=node.id,
                relationship=RelationshipType.CONTAINS,
                evidence={"tier": "static_scan", "source": _SOURCE},
            )
        )
    _membership(graph, records, scope)
    _local_edges(graph, records, by_name)


def _local_edges(graph: UnifiedGraph, records: list[dict[str, Any]], by_name: dict[tuple[str, str], list[str]]) -> None:
    by_path: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in records:
        by_path[(row["ecosystem"], row["path"])].append(row["id"])
    for row in records:
        names = row.get("workspace_dependencies", [])
        paths = row.get("local_dependency_paths", {})
        targets = [by_name.get((row["ecosystem"], n), []) for n in names[:1000] if isinstance(n, str)] if isinstance(names, list) else []
        if isinstance(paths, dict):
            targets += [by_path.get((row["ecosystem"], p), []) for p in list(paths.values())[:1000] if isinstance(p, str)]
        for candidates in targets:
            if len(candidates) == 1 and candidates[0] != row["id"]:
                graph.add_edge(
                    UnifiedEdge(
                        source=row["id"],
                        target=candidates[0],
                        relationship=RelationshipType.DEPENDS_ON,
                        evidence={
                            "source": _SOURCE,
                            "tier": "static_scan",
                            "basis": "workspace_declaration",
                            "artifact": row.get("manifest"),
                        },
                    )
                )


def _membership(graph: UnifiedGraph, records: list[dict[str, Any]], scope: str) -> None:
    files = (
        n
        for n in graph.nodes.values()
        if n.entity_type in {EntityType.CONFIG_FILE, EntityType.SOURCE_FILE} and n.attributes.get("repository_scope") == scope
    )
    for file in files:
        path = str(file.attributes.get("path") or "")
        candidates = [r for r in records if r["path"] == "." or path.startswith(r["path"] + "/")]
        if not candidates:
            continue
        longest = max(len(r["path"]) for r in candidates)
        owners = [r for r in candidates if len(r["path"]) == longest]
        # A mixed-language folder can have multiple package manifests. A file
        # with no uniquely recorded owner is left unresolved instead of fan-out.
        owners = [r for r in owners if r.get("manifest") == path] or owners
        if len(owners) != 1:
            continue
        owner = owners[0]
        graph.add_edge(
            UnifiedEdge(
                source=file.id,
                target=owner["id"],
                relationship=RelationshipType.BELONGS_TO,
                evidence={"tier": "static_scan", "source": _SOURCE, "basis": "nearest_workspace_directory"},
            )
        )
        for edge in list(graph.adjacency.get(file.id, [])):
            target = graph.nodes.get(edge.target)
            if edge.relationship == RelationshipType.DEPENDS_ON and target and target.entity_type == EntityType.PACKAGE:
                names = owner.get("declared_dependencies", [])
                if target.label not in names and target.attributes.get("name") not in names:
                    continue
                if target.attributes.get("ecosystem") != owner["ecosystem"]:
                    continue
                graph.add_edge(
                    UnifiedEdge(
                        source=owner["id"],
                        target=target.id,
                        relationship=RelationshipType.DEPENDS_ON,
                        evidence={"tier": "static_scan", "source": _SOURCE, "artifact": path, "basis": "recorded_manifest_dependency"},
                    )
                )
        for edge in list(graph.reverse_adjacency.get(file.id, [])):
            finding = graph.nodes.get(edge.source)
            if (
                edge.relationship == RelationshipType.AFFECTS
                and finding
                and finding.entity_type in {EntityType.VULNERABILITY, EntityType.MISCONFIGURATION}
            ):
                graph.add_edge(
                    UnifiedEdge(
                        source=finding.id,
                        target=owner["id"],
                        relationship=RelationshipType.BELONGS_TO,
                        evidence={"tier": "static_scan", "source": _SOURCE, "artifact": path, "basis": "finding_file_membership"},
                    )
                )
