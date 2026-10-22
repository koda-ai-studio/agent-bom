"""Scoped dashboard membership evidence; never a claim of effective access."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.platform_directory_ids import MAX_RECORDS, directory_node_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text

_COVERAGE_FIELDS = ("capability", "state", "complete", "read", "observed_at", "pages_read")


def _text(value: Any) -> str:
    return value if isinstance(value, str) and value.strip() == value and 0 < len(value) <= 512 else ""


def _membership(graph: UnifiedGraph, source: str, target: str, evidence: dict[str, Any]) -> None:
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.MEMBER_OF, traversable=False, evidence=evidence))


def project_platform_directory(graph: UnifiedGraph, inventory: dict[str, Any], *, provider: str) -> None:
    """Preserve recorded principals, configured roles and read gaps in their own account."""
    directory = inventory.get("directory")
    account = _text(inventory.get("account_id"))
    account_node = f"account:{provider}:{account}"
    if not account or account_node not in graph.nodes or not isinstance(directory, dict):
        return
    if directory.get("provider") != provider or directory.get("account_id") != account:
        return
    members, grants, coverage = (directory.get(key, []) for key in ("identities", "grants", "coverage"))
    if not all(isinstance(rows, list) and len(rows) <= MAX_RECORDS for rows in (members, grants, coverage)):
        return
    source = f"{provider}-management"
    account_record = graph.nodes[account_node]
    account_record.attributes.update(
        {
            "canonical_id": account_node,
            "directory_coverage": [{k: row[k] for k in _COVERAGE_FIELDS if k in row} for row in coverage if isinstance(row, dict)],
            "service_identities_state": "not_collected",
            "cross_account_trust_state": "not_collected",
            "observed_communication_state": "not_collected",
        }
    )
    # Project references remain references, not invented resource metadata.
    refs = directory.get("project_refs", [])
    if isinstance(refs, list) and len(refs) <= MAX_RECORDS:
        account_record.attributes["directory_project_refs"] = [value for value in refs if _text(value)]
    if _text(directory.get("name")):
        account_record.label = directory["name"]
    observed_at = next(
        (row.get("observed_at") for row in coverage if isinstance(row, dict) and row.get("capability") == "organization_members"), None
    )
    evidence = {
        "source": source,
        "basis": "configured_membership",
        "tier": "recorded",
        "effective_access": "not_evaluated",
        "source_observed_at": observed_at,
    }
    eligible, rejected = _eligible_members(members, provider, account)
    account_record.attributes["directory_projection_state"] = "incomplete" if rejected else "complete"
    account_record.attributes["directory_unresolved_members"] = rejected
    grant_keys = {
        (_text(g.get("principal_id")), _text(g.get("role")))
        for g in grants
        if isinstance(g, dict)
        and g.get("account_id") == account
        and g.get("basis") == "configured_membership"
        and g.get("effective_access") == "not_evaluated"
        and (provider != "vercel" or g.get("confirmed") is True)
    }
    for member in eligible:
        _project_member(graph, member, provider, account, account_node, source, evidence, grant_keys)


def _eligible_members(members: list[Any], provider: str, account: str) -> tuple[list[dict[str, Any]], int]:
    """Conflicting or redacted native identities remain unresolved, never guessed."""
    unique: dict[str, dict[str, Any]] = {}
    conflicts: set[str] = set()
    rejected = 0
    for member in members:
        if not isinstance(member, dict) or member.get("provider") != provider or member.get("account_id") != account:
            rejected += 1
            continue
        native, role = _text(member.get("native_id")), _text(member.get("role"))
        if not native or not role or "<redacted>" in native or sanitize_text(native) != native:
            rejected += 1
            continue
        if native in unique and unique[native] != member:
            conflicts.add(native)
        unique[native] = member
    return [m for native, m in unique.items() if native not in conflicts], rejected + len(conflicts)


def _project_member(
    graph: UnifiedGraph,
    member: dict[str, Any],
    provider: str,
    account: str,
    account_node: str,
    source: str,
    evidence: dict[str, Any],
    grants: set[tuple[str, str]],
) -> None:
    native, role = _text(member.get("native_id")), _text(member.get("role"))
    user_id = directory_node_id(provider, account, "user", native)
    attributes: dict[str, Any] = {
        "canonical_id": user_id,
        "native_id": native,
        "cloud_provider": provider,
        "account_id": account,
        "recorded_role": role,
    }
    attributes.update({key: member[key] for key in ("name", "email") if _text(member.get(key))})
    attributes.update({key: member[key] for key in ("confirmed", "mfa_enabled") if type(member.get(key)) is bool})
    graph.add_node(
        UnifiedNode(
            id=user_id,
            entity_type=EntityType.USER,
            label=_text(member.get("name")) or native,
            attributes=attributes,
            data_sources=[source],
            dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
        )
    )
    # A pending invitation is inventory, not proof of an accepted role.
    if provider == "vercel" and member.get("confirmed") is not True:
        return
    _membership(graph, user_id, account_node, dict(evidence))
    if (user_id, role) not in grants:
        return
    role_id = directory_node_id(provider, account, "role", role)
    graph.add_node(
        UnifiedNode(
            id=role_id,
            entity_type=EntityType.ROLE,
            label=role,
            attributes={
                "canonical_id": role_id,
                "cloud_provider": provider,
                "account_id": account,
                "role_name": role,
                "effective_access": "not_evaluated",
            },
            data_sources=[source],
            dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
        )
    )
    _membership(graph, user_id, role_id, {**evidence, "role": role, "confirmed": member.get("confirmed")})
