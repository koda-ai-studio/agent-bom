"""Credential-slot and explicitly evidenced identity relationships for MCP servers."""

from collections.abc import Mapping
from typing import Any

from agent_bom.canonical_ids import canonical_graph_node_id, source_ids
from agent_bom.constants import is_credential_key as _is_credential_key
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation_scope import runtime_stable_identity
from agent_bom.graph.credential_identity import slot_receipt
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def project_credentials(
    graph: UnifiedGraph, srv_dict: Mapping[str, Any], srv_id: str, tool_ids: list[str], data_source_tag: str, *, configured_by: str = ""
) -> None:
    env_keys = srv_dict.get("credential_env_vars", [])
    if not env_keys:
        env_dict = srv_dict.get("env", {})
        if isinstance(env_dict, dict):
            env_keys = [k for k in env_dict if _is_credential_key(k)]
    for env_key in env_keys:
        cred_id = f"cred:{srv_id}:{env_key}"
        _add_credential(graph, cred_id, srv_id, env_key, tool_ids, data_source_tag, configured_by)


def _add_credential(
    graph: UnifiedGraph, cred_id: str, srv_id: str, env_key: str, tool_ids: list[str], data_source_tag: str, configured_by: str
) -> None:
    server = graph.nodes.get(srv_id)
    occurrence = slot_receipt(env_key, runtime_stable_identity(server, scan_id=graph.scan_id)) if server is not None else None
    graph.add_node(
        UnifiedNode(
            id=cred_id,
            entity_type=EntityType.CREDENTIAL,
            label=env_key,
            attributes={
                "canonical_id": canonical_graph_node_id(EntityType.CREDENTIAL.value, cred_id),
                "source_ids": source_ids(env_key=env_key, server_id=srv_id),
                "server": srv_id,
                "servers": [srv_id],
                "credential_occurrence": occurrence,
            },
            data_sources=[data_source_tag],
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=srv_id,
            target=cred_id,
            relationship=RelationshipType.EXPOSES_CRED,
            weight=2.0,
            evidence={
                **edge_evidence(data_source_tag or "agent_discovery", "static_scan"),
                **({"configured_by": [configured_by]} if configured_by else {}),
            },
        )
    )
    for tool_id in tool_ids:
        graph.add_edge(
            UnifiedEdge(
                source=cred_id,
                target=tool_id,
                relationship=RelationshipType.REACHES_TOOL,
                evidence={
                    "source": data_source_tag,
                    "tier": "static_scan",
                    "server": srv_id,
                    "credential_env_var": env_key,
                    "mapping_method": "server_scope_conservative",
                    "confidence": "medium",
                },
            )
        )
