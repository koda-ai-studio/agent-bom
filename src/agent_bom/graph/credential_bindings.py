"""Resolve explicit credential references after native cloud inventory is projected.

Exact graph/canonical IDs can join a path. Names never confer identity, and
ambiguous IDs remain non-traversable candidates on a separate configured node.
"""

from collections import defaultdict
from collections.abc import Mapping
from hashlib import sha256
from typing import Any

from agent_bom.canonical_ids import agent_graph_id_for, mcp_server_graph_id_for
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _is_sbom_import
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text

_IDENTITIES = {EntityType.MANAGED_IDENTITY, EntityType.SERVICE_ACCOUNT, EntityType.SERVICE_PRINCIPAL, EntityType.ROLE}


def _provider(node: UnifiedNode) -> str:
    return str(node.attributes.get("cloud_provider") or node.attributes.get("provider") or node.dimensions.cloud_provider or "").lower()


def _reference(binding: Mapping) -> str:
    return sanitize_text(str(binding.get("identity_canonical_id") or "").strip())


def project_credential_bindings(graph: UnifiedGraph, agents: list[dict[str, Any]], source: str) -> None:
    """Build the index once; native IDs shadow aliases and provider conflicts fail closed."""
    references = {
        _reference(binding)
        for agent in agents
        for server in agent.get("mcp_servers", [])
        for binding in server.get("identity_bindings", [])
        if isinstance(binding, Mapping)
    } - {""}
    if not references:
        return
    # Snapshot membership before adding placeholders, without retaining every
    # node object and defeating the store-backed graph's bounded working set.
    native_ids = {reference for reference in references if graph.get_node(reference) is not None}
    canonical: dict[str, list[str]] = defaultdict(list)
    for node in graph.nodes.values():
        alias = node.attributes.get("canonical_id")
        if node.entity_type in _IDENTITIES and isinstance(alias, str) and alias in references:
            canonical[alias].append(node.id)
    for agent in agents:
        for server in agent.get("mcp_servers", []):
            server_id = agent_graph_id_for(agent) if _is_sbom_import(agent) else mcp_server_graph_id_for(server, agent)
            for binding in server.get("identity_bindings", []):
                if not isinstance(binding, Mapping):
                    continue
                env_key = binding.get("credential_ref")
                credential = graph.get_node(f"cred:{server_id}:{env_key}")
                if credential is None or credential.entity_type is not EntityType.CREDENTIAL:
                    continue
                _project_binding(graph, credential.id, binding, canonical, native_ids, source)


def _project_binding(
    graph: UnifiedGraph,
    credential: str,
    binding: Mapping,
    canonical: dict[str, list[str]],
    native_ids: set[str],
    source: str,
) -> None:
    reference = _reference(binding)
    evidence_source = sanitize_text(str(binding.get("evidence_source") or "").strip())
    provider = sanitize_text(str(binding.get("provider") or "").strip().lower())
    if not reference or not evidence_source:
        return
    # Placeholders added by earlier bindings cannot become new identity evidence.
    direct = reference in native_ids
    # A conflicting live node must never redirect through a shadowing alias.
    ids = [reference] if direct else canonical.get(reference, [])
    matches = [
        node_id
        for node_id in ids
        if (node := graph.get_node(node_id)) is not None
        and node.entity_type in _IDENTITIES
        and (not provider or _provider(node) == provider)
    ]
    basis = "exact_node_id" if direct else "exact_canonical_id"
    if len(matches) == 1:
        target = matches[0]
    else:
        basis = "ambiguous_canonical_id" if matches else "unresolved_identity_reference"
        target = reference
        if graph.get_node(reference) is not None:
            digest = sha256(f"{credential}\0{provider}\0{reference}".encode()).hexdigest()
            target = f"configured_identity:{digest}"
        graph.add_node(
            UnifiedNode(
                id=target,
                entity_type=EntityType.MANAGED_IDENTITY,
                label=reference.rsplit(":", 1)[-1],
                attributes={
                    "canonical_id": target,
                    "provider": provider,
                    "evidence_source": evidence_source,
                    "credential_ref": binding.get("credential_ref"),
                    "reported_identity_ref": reference,
                    "identity_match_basis": basis,
                },
                data_sources=[source, evidence_source],
                dimensions=NodeDimensions(cloud_provider=provider),
            )
        )
        _project_candidates(graph, target, matches, basis, evidence_source, reference)
    graph.add_edge(
        UnifiedEdge(
            source=credential,
            target=target,
            relationship=RelationshipType.AUTHENTICATES_AS,
            confidence=1.0,
            evidence={
                "source": evidence_source,
                "tier": "modeled_infrastructure",
                "credential_ref": binding.get("credential_ref"),
                "mapping_method": "explicit_identity_binding",
                "confidence": "high",
                "identity_match_basis": basis,
                "reported_identity_ref": reference,
                "execution_proven": False,
            },
        )
    )


def _project_candidates(graph: UnifiedGraph, target: str, matches: list[str], basis: str, source: str, reference: str) -> None:
    for candidate in sorted(matches):
        graph.add_edge(
            UnifiedEdge(
                source=target,
                target=candidate,
                relationship=RelationshipType.POSSIBLY_CORRELATES_WITH,
                confidence=0.0,
                evidence={
                    "source": source,
                    "tier": "modeled_infrastructure",
                    "identity_match_basis": basis,
                    "execution_proven": False,
                    "reported_identity_ref": reference,
                },
            )
        )
