"""Public finding fields restored past default-deny response redaction.

Each field is rebuilt from a bounded allowlist or a static catalog, never echoed
from free-text row content: scanner rows can embed paths or configuration values.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from typing import Any

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
