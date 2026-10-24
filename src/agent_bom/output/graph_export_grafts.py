"""Entity types the graph export grafts from the unified builder."""

from __future__ import annotations

# Entity types only the unified builder produces (cloud inventory, CIEM, CIS,
# Snowflake, RBAC), grafted so `agent-bom graph` shows the cloud estate. Cloud
# AI assets (hosted agents, endpoints, model deployments, prompt templates) are
# typed agent/server/model/config_file; the base projection already carries the
# MCP inventory under the same ids, so only the estate's own nodes graft.
CLOUD_ENTITY_TYPES = frozenset(
    {
        "cloud_resource",
        "agent",
        "server",
        "model",
        "config_file",
        "resource",
        "data_store",
        "misconfiguration",
        "org",
        "account",
        "user",
        "group",
        "role",
        "policy",
        "service_account",
        "service_principal",
        "federated_identity",
        "access_grant",
        "access_policy",
        "environment",
        "fleet",
        "cluster",
        "infra",
    }
)
