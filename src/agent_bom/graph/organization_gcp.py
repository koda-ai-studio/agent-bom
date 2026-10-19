"""GCP organization hierarchy, inherited IAM and organization-policy projection."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.cloud_context import _add_identity_node
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _add_gcp_organization(
    graph: UnifiedGraph,
    payload: Any,
    data_source: str,
    *,
    allow_heuristic_authorization: bool = True,
) -> None:
    """Promote the GCP Organization (org → folders → projects) into the graph.

    The GCP analogue of :func:`_add_aws_organization` and the Azure
    management-group hierarchy: the estate as a navigable ``CONTAINS`` roll-up
    backbone — org → folder → project(ACCOUNT) → resources — with org/folder IAM
    bindings attached as ``HAS_PERMISSION`` edges (privilege classified, inherited
    DOWN to every child project) and org-policy constraints as ``GOVERNS`` edges.

    Project nodes use the same ``account:gcp:<project_id>`` id a per-project
    inventory emits, so the org structure and any inventoried project graph stitch
    together. Scales to the org/folder project budget. Never raises; a non-ok
    payload is a no-op.
    """
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return
    data_sources = sorted({data_source, "gcp-organizations"} - {""})
    org_id = _clean_graph_part(payload.get("org_id"))
    org_node_id = f"org:gcp:{org_id}" if org_id else "org:gcp:organization"
    graph.add_node(
        UnifiedNode(
            id=org_node_id,
            entity_type=EntityType.ORG,
            label=f"GCP org: {_clean_graph_part(payload.get('org_name')) or org_id or 'organization'}",
            attributes={
                "org_id": org_id,
                "org_name": _clean_graph_part(payload.get("org_name")),
                "cloud_provider": "gcp",
            },
            data_sources=data_sources,
            dimensions=NodeDimensions(cloud_provider="gcp", surface="identity"),
        )
    )

    # Folders (the FOLDER tier of the CONTAINS tree). A folder's parent is the org
    # or another folder; map both to their node ids.
    folder_ids = {_clean_graph_part(f.get("id")) for f in (payload.get("folders") or []) if isinstance(f, dict)}
    _project_gcp_folders(graph, payload, data_sources, org_node_id, folder_ids)

    _project_gcp_projects(graph, payload, data_sources, org_node_id, folder_ids)

    _project_gcp_bindings(graph, payload, data_sources, org_node_id, allow_heuristic_authorization)

    _project_gcp_policies(graph, payload, data_sources, org_node_id)


def _folder_node_id(folder_id: str) -> str:
    # folder_id is the resource name "folders/123"; keep it stable + readable.
    return f"org:gcp:folder:{folder_id.rsplit('/', 1)[-1]}"


def _project_gcp_folders(
    graph: UnifiedGraph, payload: dict[str, Any], data_sources: list[str], org_node_id: str, folder_ids: set[str]
) -> None:
    for folder in payload.get("folders", []) or []:
        if not isinstance(folder, dict):
            continue
        folder_id = _clean_graph_part(folder.get("id"))
        if not folder_id:
            continue
        node_id = _folder_node_id(folder_id)
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.ORG,
                label=f"folder: {_clean_graph_part(folder.get('name')) or folder_id}",
                attributes={"folder_id": folder_id, "cloud_provider": "gcp"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="gcp", surface="identity"),
            )
        )
        parent = _clean_graph_part(folder.get("parent_id"))
        parent_node = _folder_node_id(parent) if parent in folder_ids else org_node_id
        _add_rel_edge(graph, parent_node, node_id, RelationshipType.CONTAINS, {"source": "gcp-organizations"})


def _project_gcp_projects(
    graph: UnifiedGraph, payload: dict[str, Any], data_sources: list[str], org_node_id: str, folder_ids: set[str]
) -> None:
    # Projects (the ACCOUNT tier). Same node id a per-project scan emits so the
    # org tree and inventoried project graphs stitch together.
    for project in payload.get("projects", []) or []:
        if not isinstance(project, dict):
            continue
        project_id = _clean_graph_part(project.get("id"))
        if not project_id:
            continue
        project_node = _add_identity_node(
            graph,
            EntityType.ACCOUNT,
            project_id,
            "gcp",
            data_sources,
            label=f"project: {_clean_graph_part(project.get('name')) or project_id}",
            account_id=project_id,
            cloud_provider="gcp",
            account_name=_clean_graph_part(project.get("name")),
            project_number=_clean_graph_part(project.get("number")),
        )
        parent = _clean_graph_part(project.get("parent_id"))
        parent_node = _folder_node_id(parent) if parent in folder_ids else org_node_id
        _add_rel_edge(graph, parent_node, project_node, RelationshipType.CONTAINS, {"source": "gcp-organizations"})


def _project_gcp_bindings(
    graph: UnifiedGraph, payload: dict[str, Any], data_sources: list[str], org_node_id: str, allow_heuristic_authorization: bool
) -> None:
    # Org/folder IAM bindings → HAS_PERMISSION from each member to the scope node
    # (these grant DOWN to every child project — inherited permissions).
    _GCP_PRINCIPAL_ENTITY = {  # noqa: N806 — local constant lookup
        "serviceaccount": EntityType.SERVICE_ACCOUNT,
        "user": EntityType.USER,
        "group": EntityType.USER,
    }
    for binding in (payload.get("iam_bindings", []) or []) if allow_heuristic_authorization else ():
        if not isinstance(binding, dict):
            continue
        role = _clean_graph_part(binding.get("role"))
        scope_id = _clean_graph_part(binding.get("scope_id"))
        if not role or not scope_id:
            continue
        scope_level = str(binding.get("scope_level", "") or "").lower()
        scope_node = org_node_id if scope_level == "organization" else _folder_node_id(scope_id)
        if scope_node not in graph.nodes:
            continue
        privilege = str(binding.get("privilege_level", "") or "unknown")
        for member in binding.get("members", []) or []:
            member = str(member or "").strip()
            if not member:
                continue
            prefix, _, identity = member.partition(":")
            identity = (identity or member).strip().lower()
            if not identity:
                continue
            entity = _GCP_PRINCIPAL_ENTITY.get(prefix.strip().lower().replace("-", "").replace("_", ""), EntityType.USER)
            principal_node = _add_identity_node(
                graph,
                entity,
                identity,
                "gcp",
                data_sources,
                label=f"{prefix or 'principal'}: {identity}",
                principal_id=identity,
                cloud_provider="gcp",
            )
            graph.add_edge(
                UnifiedEdge(
                    source=principal_node,
                    target=scope_node,
                    relationship=RelationshipType.HAS_PERMISSION,
                    evidence={
                        "source": "gcp-organizations",
                        "role": role,
                        "scope": scope_id,
                        "scope_level": scope_level,
                        "privilege_level": privilege,
                        "privileged": privilege == "admin",
                        "inherited": True,
                    },
                )
            )


def _project_gcp_policies(graph: UnifiedGraph, payload: dict[str, Any], data_sources: list[str], org_node_id: str) -> None:
    # Org-policy constraints → GOVERNS the scope they apply to (the AWS-SCP analogue).
    for policy in payload.get("org_policies", []) or []:
        if not isinstance(policy, dict):
            continue
        constraint = _clean_graph_part(policy.get("constraint")) or _clean_graph_part(policy.get("id"))
        scope_id = _clean_graph_part(policy.get("scope_id"))
        if not constraint or not scope_id:
            continue
        policy_node = f"policy:gcp:orgpolicy:{constraint}"
        graph.add_node(
            UnifiedNode(
                id=policy_node,
                entity_type=EntityType.POLICY,
                label=f"org policy: {constraint}",
                attributes={"constraint": constraint, "cloud_provider": "gcp"},
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider="gcp", surface="identity"),
            )
        )
        _add_rel_edge(graph, org_node_id, policy_node, RelationshipType.OWNS, {"source": "gcp-organizations"})
        scope_is_org = scope_id.startswith("organizations/")
        scope_node = org_node_id if scope_is_org else _folder_node_id(scope_id)
        if scope_node in graph.nodes:
            _add_rel_edge(graph, policy_node, scope_node, RelationshipType.GOVERNS, {"source": "gcp-organizations"})
