"""Public finding fields restored past default-deny response redaction.

Each field is rebuilt from a bounded allowlist or a static catalog, never echoed
from free-text row content: scanner rows can embed paths or configuration values.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from agent_bom.atlas import ATLAS_TECHNIQUES

_PROVENANCE_KEYS = frozenset(
    {
        "source",
        "source_type",
        "collector",
        "provider",
        "service",
        "observed_via",
        "observed_at",
        "confidence",
        "scan_id",
        "job_id",
        "schema_version",
    }
)


@lru_cache(maxsize=1)
def _toxic_rule_remediation() -> dict[str, str]:
    from agent_bom.graph.toxic_findings import TOXIC_RULES

    return {rule.id: rule.remediation for rule in TOXIC_RULES}


def safe_finding_provenance(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    from agent_bom.security import sanitize_sensitive_payload

    bounded = {str(key): raw for key, raw in value.items() if str(key) in _PROVENANCE_KEYS}
    sanitized = sanitize_sensitive_payload(bounded, max_str_len=128)
    if not isinstance(sanitized, dict):
        return None
    return sanitized or None


def catalog_remediation(row: Mapping[str, Any]) -> str | None:
    """Guidance for graph combination findings, looked up by toxic-rule id."""
    if row.get("finding_type") != "COMBINATION" or row.get("source") != "GRAPH_ANALYSIS":
        return None
    evidence = row.get("evidence")
    rule_id = evidence.get("rule_id") if isinstance(evidence, Mapping) else None
    if not isinstance(rule_id, str):
        return None
    return _toxic_rule_remediation().get(rule_id)


def restored_public_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    reachability = row.get("reachability")
    if isinstance(reachability, str) and reachability in {"confirmed", "likely", "unknown", "unlikely"}:
        fields["reachability"] = reachability
    if (provenance := safe_finding_provenance(row.get("provenance"))) is not None:
        fields["provenance"] = provenance
    if (guidance := catalog_remediation(row)) is not None:
        fields["remediation_guidance"] = guidance
    return fields


def safe_atlas_mapping_evidence(value: Any) -> dict[str, dict[str, Any]]:
    """Restore only structural, scan-time catalog associations, never raw evidence."""
    if not isinstance(value, Mapping):
        return {}
    result = {}
    for technique in ATLAS_TECHNIQUES:
        receipt = value.get(technique)
        if (
            not isinstance(receipt, Mapping)
            or receipt.get("basis") != "catalog_weakness_association"
            or receipt.get("execution_proven") is not False
        ):
            continue
        hashes = {key: receipt.get(key) for key in ("atlas_catalog_sha256", "attack_catalog_sha256")}
        if any(not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None for digest in hashes.values()):
            continue
        attack = receipt.get("attack_reference")
        if not isinstance(attack, str) or re.fullmatch(r"T\d{4}(?:\.\d{3})?", attack) is None:
            continue
        cwes = receipt.get("cwe_ids")
        if not isinstance(cwes, list):
            continue
        safe_cwes = sorted({cwe for cwe in cwes[:100] if isinstance(cwe, str) and re.fullmatch(r"CWE-\d{1,6}", cwe)})
        if not safe_cwes:
            continue
        version = receipt.get("atlas_version")
        result[technique] = {
            "basis": "catalog_weakness_association",
            "execution_proven": False,
            "cwe_ids": safe_cwes,
            "attack_reference": attack,
            **hashes,
            "atlas_version": version if isinstance(version, str) and re.fullmatch(r"\d{1,4}(?:\.\d{1,4}){1,3}", version) else "unknown",
            "technique_url": f"https://atlas.mitre.org/techniques/{technique}",
        }
    return result


def restore_atlas_receipts(payload: dict[str, Any], row: Mapping[str, Any]) -> None:
    raw = row.get("evidence")
    if isinstance(raw, Mapping) and (receipts := safe_atlas_mapping_evidence(raw.get("atlas_mapping_evidence"))):
        payload.setdefault("evidence", {})["atlas_mapping_evidence"] = receipts


def frozen_atlas_mapping_fields(br: object) -> dict:
    """Project only scan-time receipts; never re-map a historical finding."""
    receipts = getattr(br, "atlas_mapping_evidence", {})
    supported = {tag: receipts[tag] for tag in getattr(br, "atlas_tags", []) if tag in receipts}
    return {"atlas_mapping_evidence": supported} if supported else {}


_PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9@._/+:-]{1,256}")


def safe_lineage_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """Dependency lineage (direct?, depth, parent package) of a package-backed finding.

    Read from the row or, for rows that kept it only in evidence, from the same
    ``package_*`` evidence the graph projects. Absent for non-package findings.
    """
    raw_evidence = row.get("evidence")
    evidence: Mapping[str, Any] = raw_evidence if isinstance(raw_evidence, Mapping) else {}
    out: dict[str, Any] = {}
    is_direct = row.get("is_direct", evidence.get("package_is_direct"))
    if isinstance(is_direct, bool):
        out["is_direct"] = is_direct
    depth = row.get("dependency_depth", evidence.get("package_dependency_depth"))
    if isinstance(depth, int) and not isinstance(depth, bool) and 0 <= depth <= 1_000:
        out["dependency_depth"] = depth
    if out:
        parent = row.get("introduced_via", evidence.get("package_parent"))
        out["introduced_via"] = parent if isinstance(parent, str) and _PACKAGE_NAME_RE.fullmatch(parent) else None
    return out
