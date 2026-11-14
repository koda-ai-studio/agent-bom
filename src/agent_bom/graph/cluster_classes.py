"""Which group of the grouped full map a node belongs to.

Groups follow the estate from the outside in — cloud scope, then the AI layer
(agents), MCP servers and tools, packages by ecosystem, findings by severity,
identities and credentials, then cloud and data resources by type — so the map
reads left to right in the order an exposure travels. A group key depends only
on the node's own stored fields, so a store can derive it from one row.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from agent_bom.core.severity import SEVERITY_RANK

FINDING_TYPES: frozenset[str] = frozenset({"vulnerability", "misconfiguration", "drift_incident"})

# (tier, tier label): the column a group is drawn in.
TIERS: tuple[str, ...] = (
    "Scope",
    "AI layer",
    "MCP servers and tools",
    "Packages",
    "Findings",
    "Identity and credentials",
    "Cloud and data",
    "Code and CI",
    "Other",
)

_TIER_OF_TYPE: dict[str, int] = {
    **dict.fromkeys(("provider", "org", "account", "environment", "fleet"), 0),
    **dict.fromkeys(("agent", "model", "framework", "eval_suite", "application", "user", "group"), 1),
    **dict.fromkeys(("server", "tool", "tool_call", "resource", "api_gateway"), 2),
    "package": 3,
    **dict.fromkeys(tuple(FINDING_TYPES), 4),
    **dict.fromkeys(
        (
            "credential",
            "credential_ref",
            "role",
            "policy",
            "service_account",
            "service_principal",
            "federated_identity",
            "managed_identity",
            "access_grant",
            "access_policy",
            "blueprint",
        ),
        5,
    ),
    **dict.fromkeys(("cloud_resource", "container", "cluster", "data_store", "dataset"), 6),
    **dict.fromkeys(("source_file", "code_module", "config_file", "external_import", "ci_job", "directory"), 7),
}

_TYPE_LABELS: dict[str, str] = {
    "provider": "Providers",
    "org": "Organizations",
    "account": "Accounts",
    "environment": "Environments",
    "fleet": "Fleets",
    "agent": "Agents",
    "model": "Models",
    "framework": "Frameworks",
    "eval_suite": "Eval suites",
    "application": "Applications",
    "user": "Users",
    "group": "Groups",
    "server": "MCP servers",
    "tool": "Tools",
    "tool_call": "Tool calls",
    "resource": "MCP resources",
    "api_gateway": "API gateways",
    "credential": "Credentials",
    "credential_ref": "Credential references",
    "role": "Roles",
    "policy": "Policies",
    "service_account": "Service accounts",
    "service_principal": "Service principals",
    "federated_identity": "Federated identities",
    "managed_identity": "Managed identities",
    "access_grant": "Access grants",
    "access_policy": "Access policies",
    "blueprint": "Blueprints",
    "container": "Containers",
    "cluster": "Clusters",
    "data_store": "Data stores",
    "dataset": "Datasets",
    "source_file": "Source files",
    "code_module": "Code modules",
    "config_file": "Config files",
    "external_import": "External imports",
    "ci_job": "CI jobs",
    "directory": "Directories",
}

#: Severity buckets for findings, worst first; anything else is "unrated".
FINDING_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY_WORDS: dict[int, str] = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info", 0: "none"}
#: A group holding a finding at or above this rank, or a hop of an attack path, leads the map.
RISKY_RANK = SEVERITY_RANK["high"]


@dataclass(frozen=True, slots=True)
class GroupClass:
    key: str
    label: str
    tier: int


def _clean(value: object) -> str:
    return str(value or "").strip().lower()[:64]


def severity_rank(severity: object) -> int:
    return SEVERITY_RANK.get(_clean(severity), 0)


def classify(entity_type: str, severity: str = "", ecosystem: str = "", resource_type: str = "") -> GroupClass:
    """The group a node with these stored fields belongs to."""
    return _classify(str(entity_type or ""), str(severity or ""), str(ecosystem or ""), str(resource_type or ""))


@lru_cache(maxsize=8192)
def _classify(entity_type: str, severity: str, ecosystem: str, resource_type: str) -> GroupClass:
    kind = _clean(entity_type)
    tier = _TIER_OF_TYPE.get(kind, len(TIERS) - 1)
    if kind == "package":
        eco = _clean(ecosystem) or "unknown"
        return GroupClass(f"package:{eco}", f"Packages · {eco if eco != 'unknown' else 'unknown ecosystem'}", tier)
    if kind in FINDING_TYPES:
        sev = SEVERITY_WORDS.get(severity_rank(severity), "none")
        bucket = sev if sev in FINDING_SEVERITIES else "unrated"
        return GroupClass(f"finding:{bucket}", f"Findings · {bucket}", tier)
    if kind == "cloud_resource":
        rtype = _clean(resource_type) or "untyped"
        return GroupClass(f"cloud_resource:{rtype}", f"Cloud resources · {rtype.replace('_', ' ')}", tier)
    label = _TYPE_LABELS.get(kind, kind.replace("_", " ").capitalize() or "Unknown")
    return GroupClass(f"type:{kind}", label, tier)


__all__ = ["FINDING_TYPES", "GroupClass", "RISKY_RANK", "SEVERITY_WORDS", "TIERS", "classify", "severity_rank"]
