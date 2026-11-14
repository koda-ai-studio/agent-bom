"""Shared vocabulary of report schema 2.0: versions, transform names, the fields each reference covers, and the errors.

See :mod:`agent_bom.output.report_packing` for the format.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

REPORT_SCHEMA_V1 = "1.0"
REPORT_SCHEMA_V2 = "2.0"
PACKING_SCHEMA_VERSION = "1"
REPORT_SCHEMA_VERSIONS = (REPORT_SCHEMA_V1, REPORT_SCHEMA_V2)
T_PROVENANCE = "provenance_refs"
T_CONTROLS = "compliance_control_refs"
T_ROOT_PACKAGES = "root_packages_alias"
T_INVENTORY_PACKAGES = "inventory_snapshot_packages"
T_PACKAGES = "package_refs"
T_ASSETS = "asset_refs"
T_BLAST_RADIUS = "blast_radius_finding_refs"
# Pack order; expansion runs the inverses in reverse.
TRANSFORMS = (T_PROVENANCE, T_ROOT_PACKAGES, T_INVENTORY_PACKAGES, T_BLAST_RADIUS, T_ASSETS, T_PACKAGES, T_CONTROLS)
PROVENANCE_KEYS = ("discovery_provenance", "version_provenance", "package_discovery_provenance", "package_version_provenance")
PROVENANCE_REF_KEYS = {f"{key}_ref": key for key in PROVENANCE_KEYS}
# Package occurrence key -> entity row key (``ai_bom_entities.packages``).
PACKAGE_KEYS: dict[str, str] = {
    "stable_id": "id",
    **{
        key: key
        for key in (
            "canonical_id",
            "name",
            "version",
            "ecosystem",
            "purl",
            "source_package",
            "distro_name",
            "distro_version",
            "floating_reference",
            "floating_reference_reason",
            "is_malicious",
            "malicious_reason",
            "occurrence_count",
            "occurrences",
            "vulnerability_count",
            "discovery_provenance",
            "version_provenance",
            "discovery_provenance_ref",
            "version_provenance_ref",
        )
    },
}
# Finding asset key -> ``assets`` row key.
ASSET_KEYS = {
    key: key
    for key in (
        "stable_id",
        "canonical_id",
        "name",
        "asset_type",
        "identifier",
        "location",
        "provider",
        "account_ref",
        "region",
        "environment",
    )
}
# Blast-radius row key -> finding key: fields both rows derive from one vulnerability occurrence.
BLAST_RADIUS_KEYS = {
    key: key
    for key in (
        "canonical_id",
        "asset",
        "vulnerability_id",
        "severity",
        "severity_source",
        "match_confidence_tier",
        "cvss_score",
        "cvss_vector",
        "cvss_severity",
        "vendor_severity",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction",
        "network_exploitable",
        "upstream_ids",
        "epss_cve_id",
        "kev_cve_id",
        "epss_score",
        "is_kev",
        "kev_due_date",
        "is_malicious",
        "malicious_reason",
        "fixed_version",
        "risk_score",
        "unsuppressed_risk_score",
        "reachability",
        "impact_category",
        "graph_reachable",
        "graph_min_hop_distance",
        "graph_reachable_from_agents",
        "affected_agents",
        "affected_servers",
        "exposed_credentials",
        "exposed_tools",
        "ai_risk_context",
        "ai_summary",
        "attack_vector_summary",
        "suppressed",
        "suppression_id",
        "suppression_state",
        "suppression_reason",
        "vex_status",
        "vex_justification",
        "vex_source",
        "vex_suppressed",
        "owasp_tags",
        "atlas_tags",
        "attack_tags",
        "nist_ai_rmf_tags",
        "owasp_mcp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
        "cmmc_tags",
        "nist_800_53_tags",
        "fedramp_tags",
        "pci_dss_tags",
    )
}
# Expansion ceiling for documents from outside the process (pushes, MCP tool
# arguments): the PostgreSQL jsonb value limit a stored report must fit.
UNTRUSTED_MAX_EXPANDED_BYTES = 240 * 1024 * 1024
MAX_TABLE_ROWS = 1_000_000
MAX_REF_LENGTH = 512


class ReportPackingError(ValueError):
    """A schema 2.0 report whose references cannot be expanded safely."""


class ReportExpansionLimitError(ReportPackingError):
    """A schema 2.0 report whose references expand beyond the caller's byte budget."""


def is_packed(doc: object) -> bool:
    """True for a report document in schema 2.x."""
    if not isinstance(doc, Mapping):
        return False
    version = doc.get("schema_version")
    return isinstance(version, str) and version.split(".", 1)[0] == "2"


def inventory_flat_packages(snapshot: Mapping[str, Any]) -> list[Any] | None:
    agents = snapshot.get("agents")
    if not isinstance(agents, list):
        return None
    flat: list[Any] = []
    for agent in agents:
        if not isinstance(agent, dict) or not isinstance(agent.get("mcp_servers", []), list):
            return None
        for server in agent.get("mcp_servers", []):
            if not isinstance(server, dict) or not isinstance(server.get("packages", []), list):
                return None
            flat.extend(server.get("packages", []))
    return flat


def unique_index(rows: object, key: str) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    duplicate: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and isinstance(row.get(key), str):
            if row[key] in index:
                duplicate.add(row[key])
            index[row[key]] = row
    for value in duplicate:
        index.pop(value, None)
    return index


def package_occurrence_lists(doc: Mapping[str, Any]) -> Iterable[list[Any]]:
    agents = doc.get("agents")
    for agent in agents if isinstance(agents, list) else []:
        servers = agent.get("mcp_servers") if isinstance(agent, dict) else None
        for server in servers if isinstance(servers, list) else []:
            if isinstance(server, dict) and isinstance(server.get("packages"), list):
                yield server["packages"]


def package_index(doc: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    entities = doc.get("ai_bom_entities")
    return unique_index(entities.get("packages") if isinstance(entities, dict) else None, "id")


def deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: deep_copy(child) for key, child in value.items()}
    if isinstance(value, list):
        return [deep_copy(child) for child in value]
    return value
