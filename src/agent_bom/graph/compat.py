"""Map the lateral-movement context graph's node and edge kinds onto the unified schema."""

from __future__ import annotations

from agent_bom.graph.types import EntityType, RelationshipType

# Map old NodeKind values → EntityType
NODE_KIND_TO_ENTITY: dict[str, EntityType] = {
    "agent": EntityType.AGENT,
    "server": EntityType.SERVER,
    "server_cred": EntityType.SERVER,
    "server_blocked": EntityType.SERVER,
    "server_intel": EntityType.SERVER,
    "pkg": EntityType.PACKAGE,
    "cve": EntityType.VULNERABILITY,
    "credential": EntityType.CREDENTIAL,
    "tool": EntityType.TOOL,
    "vulnerability": EntityType.VULNERABILITY,
    # The context graph exposes cloud workload identities as iam_role nodes.
    "iam_role": EntityType.SERVICE_ACCOUNT,
}

# Map old EdgeKind values → RelationshipType
EDGE_KIND_TO_RELATIONSHIP: dict[str, RelationshipType] = {
    "uses": RelationshipType.USES,
    "exposes": RelationshipType.EXPOSES_CRED,
    "provides": RelationshipType.PROVIDES_TOOL,
    "vulnerable_to": RelationshipType.VULNERABLE_TO,
    "shares_server": RelationshipType.SHARES_SERVER,
    "shares_credential": RelationshipType.SHARES_CRED,
    # The context graph's iam_role -> agent attachment serializes as identity membership.
    "attached_to": RelationshipType.MEMBER_OF,
}

# Display kinds the CLI/HTML exports use for styling; each is one canonical entity type.
DISPLAY_KIND_TO_ENTITY: dict[str, EntityType] = {
    **NODE_KIND_TO_ENTITY,
    "server_clean": EntityType.SERVER,
    "server_vuln": EntityType.SERVER,
    "pkg_vuln": EntityType.PACKAGE,
    "pkg_transitive": EntityType.PACKAGE,
    "application_entrypoint": EntityType.CODE_MODULE,
}


def export_entity_type(kind: str, node_id: str = "") -> str:
    """Canonical entity type for an exported node; a display kind never leaks into ``entity_type``."""
    if kind in DISPLAY_KIND_TO_ENTITY:
        return DISPLAY_KIND_TO_ENTITY[kind].value
    try:
        return EntityType(kind).value
    except ValueError:
        pass
    if node_id.startswith("vuln:"):
        return EntityType.VULNERABILITY.value
    if kind == "finding" or node_id.startswith("misconfig:"):
        return EntityType.MISCONFIGURATION.value
    return EntityType.RESOURCE.value


def stamp_export_entity_types(elements: list[dict]) -> list[dict]:
    """Every Cytoscape node carries its canonical ``entity_type``; ``type`` stays the display kind."""
    for element in elements:
        data = element.get("data") or {}
        if "source" not in data and "id" in data:
            data.setdefault("entity_type", export_entity_type(str(data.get("type") or ""), str(data["id"])))
    return elements
