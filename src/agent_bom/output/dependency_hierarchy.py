"""Resolve recorded package parents within one observed server inventory."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_bom.core.package_lineage import DependencyRecord, resolve_dependency_edges
from agent_bom.models import Package


def package_dependency_edges(packages: list[Package]) -> tuple[list[tuple[str, str]], set[str]]:
    """Return canonical parent/child IDs and unresolved transitive IDs for model packages."""
    return resolve_dependency_edges(
        [
            DependencyRecord(
                stable_id=package.stable_id,
                name=package.name,
                ecosystem=package.ecosystem,
                is_direct=bool(package.is_direct),
                parent_package=package.parent_package,
                version_evidence=tuple(package.version_evidence),
            )
            for package in packages
        ]
    )


def cyclonedx_compositions(components: list[dict], *, incomplete: bool, unknown: bool = False) -> list[dict]:
    """Declare unresolved lineage or registry-derived inventory incomplete."""
    if not components:
        return []
    registry_resolved = any(
        component.get("type") == "library"
        and any(
            prop.get("name") == "agent-bom:resolved-from-registry" and prop.get("value") == "true"
            for prop in component.get("properties", [])
        )
        for component in components
    )
    return [
        {
            "aggregate": "unknown" if unknown else "incomplete" if registry_resolved or incomplete else "complete",
            "assemblies": [component["bom-ref"] for component in components if "bom-ref" in component],
        }
    ]


def spdx3_package_relationships(
    packages: list[Package],
    refs: dict[str, str],
    server_id: str,
    next_id: Callable[[str], str],
    annotate: Callable[[str, str], None],
) -> list[dict[str, Any]]:
    """Preserve inventory membership separately from direct dependency edges."""
    edges, unresolved = package_dependency_edges(packages)
    relationships = [
        {
            "type": "Relationship",
            "spdxId": next_id("SPDXRef-Rel"),
            "relationshipType": "dependsOn" if package.is_direct else "contains",
            "from": server_id,
            "to": [refs[package.stable_id]],
        }
        for package in packages
    ]
    relationships.extend(
        {
            "type": "Relationship",
            "spdxId": next_id("SPDXRef-Rel"),
            "relationshipType": "dependsOn",
            "from": refs[parent],
            "to": [refs[child]],
        }
        for parent, child in edges
    )
    _apply_spdx3_scopes(relationships, packages, refs)
    for package_id in sorted(unresolved):
        annotate(refs[package_id], "agent-bom:parent-resolution=unresolved")
    return relationships


def add_spdx2_package_relationships(
    packages: list[Package],
    refs: dict[str, str],
    server: dict[str, Any],
    created: str,
    add_relationship: Callable[[str, str, str], None],
) -> None:
    """Keep unresolved lineage explicit while retaining server membership."""
    for package in packages:
        add_relationship(server["SPDXID"], "DEPENDS_ON" if package.is_direct else "CONTAINS", refs[package.stable_id])
    edges, unresolved = package_dependency_edges(packages)
    for parent, child in edges:
        add_relationship(refs[parent], "DEPENDS_ON", refs[child])
    _add_spdx2_scopes(packages, refs, server["SPDXID"], edges, add_relationship)
    for package_id in sorted(unresolved):
        server.setdefault("annotations", []).append(
            {
                "annotationType": "OTHER",
                "annotator": "Tool: agent-bom",
                "annotationDate": created,
                "comment": f"agent-bom:parent-resolution=unresolved package={refs[package_id]}",
            }
        )


def cyclonedx_package_dependencies(packages: list[Package], ref_for_id: Callable[[str], str]) -> tuple[list[dict], list[str], set[str]]:
    """Render only observed direct roots and resolvable parent dependencies."""
    edges, unresolved = package_dependency_edges(packages)
    dependencies = [{"ref": ref_for_id(parent), "dependsOn": [ref_for_id(child)]} for parent, child in edges]
    roots = [ref_for_id(package.stable_id) for package in packages if package.is_direct]
    return dependencies, roots, unresolved


def imported_bom_incomplete(agents: list) -> bool:
    return any(
        isinstance(agent.metadata.get("sbom_import"), dict) and agent.metadata["sbom_import"].get("composition_complete") is False
        for agent in agents
    )


def imported_bom_unknown(agents: list) -> bool:
    return any(
        isinstance(agent.metadata.get("sbom_import"), dict) and agent.metadata["sbom_import"].get("composition_complete") is None
        for agent in agents
    )


def dependency_groups(packages: list[Package]) -> tuple[list[Package], list[Package], list[Package]]:
    """Partition direct, transitive, and unknown packages without a boolean fallback."""
    return (
        [p for p in packages if p.is_direct is True],
        [p for p in packages if p.is_direct is False],
        [p for p in packages if p.is_direct is None],
    )


def dependency_count_label(packages: list[Package], *, compact: bool = False) -> str:
    direct, transitive, unknown = dependency_groups(packages)
    if compact:
        return f" ({len(direct)} direct/{len(transitive)} transitive/{len(unknown)} unknown)" if transitive or unknown else ""
    return f"{len(direct)} direct, {len(transitive)} transitive, {len(unknown)} unknown"


def _supplied_package_scopes(packages: list[Package], refs: dict[str, str]) -> dict[str, str]:
    return {
        refs[p.stable_id]: p.dependency_scope
        for p in packages
        if any(e.get("reported_dependency_scope") not in (None, "unknown") for e in p.version_evidence)
    }


def _apply_spdx3_scopes(relationships: list[dict[str, Any]], packages: list[Package], refs: dict[str, str]) -> None:
    scopes = _supplied_package_scopes(packages, refs)
    for relation in relationships:
        scope = scopes.get(relation["to"][0])
        scope = "development" if scope == "dev" else scope
        if relation["relationshipType"] == "dependsOn" and scope in {"build", "design", "development", "other", "runtime", "test"}:
            relation.update(type="LifecycleScopedRelationship", scope=scope)


def _add_spdx2_scopes(
    packages: list[Package],
    refs: dict[str, str],
    server_id: str,
    edges: list[tuple[str, str]],
    add_relationship: Callable[[str, str, str], None],
) -> None:
    scopes = _supplied_package_scopes(packages, refs)
    parents = [(server_id, refs[p.stable_id]) for p in packages if p.is_direct is True]
    parents.extend((refs[parent], refs[child]) for parent, child in edges)
    for parent, child in parents:
        scope = scopes.get(child)
        if scope in {"runtime", "build", "dev", "test", "optional", "provided"}:
            add_relationship(child, f"{str(scope).upper()}_DEPENDENCY_OF", parent)
