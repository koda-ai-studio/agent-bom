"""Remediation text restored from static rule catalogs, never from row text.

Finding responses withhold free-text remediation because scanner rows can embed
paths or configuration values. Graph-analysis combination findings come from a
fixed rule catalog, so their guidance can be republished by rule id.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from typing import Any


@lru_cache(maxsize=1)
def _toxic_rule_remediation() -> dict[str, str]:
    from agent_bom.graph.toxic_findings import TOXIC_RULES

    return {rule.id: rule.remediation for rule in TOXIC_RULES}


def catalog_remediation(row: Mapping[str, Any]) -> str | None:
    if row.get("finding_type") != "COMBINATION" or row.get("source") != "GRAPH_ANALYSIS":
        return None
    evidence = row.get("evidence")
    rule_id = evidence.get("rule_id") if isinstance(evidence, Mapping) else None
    if not isinstance(rule_id, str):
        return None
    return _toxic_rule_remediation().get(rule_id)
