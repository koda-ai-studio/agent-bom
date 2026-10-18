"""What a ``min_severity`` floor means, defined once for every read path.

Only finding-like nodes carry a severity: a vulnerability, a misconfiguration
and a drift incident are rated, while the agents, servers, packages, cloud
resources and identities they hang off all rank 0. So a floor applied to
*every* node does not narrow the estate — it deletes the estate and leaves the
findings floating unattached, which is the difference between "here are your
critical findings and what they sit on" and "here are seven dots".

Every backend and every read path answers this one question, so it lives here
rather than being re-derived per store: :func:`node_passes_severity_floor` for
in-memory rows, :func:`severity_floor_sql` for a pushed-down WHERE fragment on
either driver's placeholder style. The SQL and the predicate are pinned against
each other by ``tests/test_graph_backend_semantics.py``.
"""

from __future__ import annotations

from typing import Any

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.applicability import SUPPRESSING_VEX_STATUSES
from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES

#: Entity types a severity floor is allowed to filter on. Everything else is
#: topology and survives any floor.
FINDING_ENTITY_VALUES: tuple[str, ...] = tuple(sorted(entity_type.value for entity_type in FINDING_ENTITY_TYPES))


def node_passes_severity_floor(
    *,
    entity_type: Any,
    severity: str = "",
    severity_id: int | None = None,
    min_severity_rank: int = 0,
) -> bool:
    """Whether a node survives ``min_severity_rank``.

    ``severity_id`` (the stored OCSF id) is preferred when a caller has it;
    both scales are 0-5 and agree, so the string is an equivalent fallback.
    """
    if not min_severity_rank:
        return True
    value = entity_type.value if hasattr(entity_type, "value") else str(entity_type)
    if value not in FINDING_ENTITY_VALUES:
        return True
    rank = int(severity_id) if severity_id is not None else SEVERITY_RANK.get((severity or "").lower(), 0)
    return rank >= min_severity_rank


def severity_floor_sql(
    min_severity_rank: int,
    *,
    column: str = "severity_id",
    entity_column: str = "entity_type",
    placeholder: str = "?",
) -> tuple[str, list[Any]]:
    """Build the same judgement as a WHERE fragment.

    ``placeholder`` is ``?`` for SQLite and ``%s`` for psycopg. Returns
    ``(sql, params)``; ``sql`` is empty when no floor is requested, so callers
    can append it unconditionally.
    """
    if not min_severity_rank:
        return "", []
    placeholders = ",".join(placeholder for _ in FINDING_ENTITY_VALUES)
    sql = f"({column} >= {placeholder} OR {entity_column} NOT IN ({placeholders}))"
    return sql, [min_severity_rank, *FINDING_ENTITY_VALUES]


#: Node-id prefixes of finding-typed overlays that restate findings counted
#: elsewhere. Legacy toxic-combination nodes (``toxic:*``) annotate CVE findings
#: already in the unified stream; the COMBINATION findings come from the graph
#: evaluator. Counting both would report one risk twice.
FINDING_COUNT_EXCLUDED_ID_PREFIXES: tuple[str, ...] = ("toxic:",)


def is_vex_suppressed_node_attributes(attributes: Any) -> bool:
    """Whether a finding node is suppressed by VEX the operator asserted.

    Same judgement as :attr:`Applicability.vex_excluded`: a ``not_affected`` /
    ``fixed`` status suppresses unless it was merely discovered in an artifact.
    """
    if not isinstance(attributes, dict):
        return False
    return attributes.get("vex_status") in SUPPRESSING_VEX_STATUSES and attributes.get("vex_source") != "discovered"


def counts_as_finding(*, entity_type: Any, node_id: str, attributes: Any = None) -> bool:
    """Whether a node contributes to finding severity counts.

    Agents and assets carry a rolled-up risk severity; counting it would
    double-count the findings beneath them. A VEX-suppressed finding is kept in
    the graph as evidence but is not an active finding, matching
    ``finding_summary``.
    """
    value = entity_type.value if hasattr(entity_type, "value") else str(entity_type)
    if value not in FINDING_ENTITY_VALUES or str(node_id).startswith(FINDING_COUNT_EXCLUDED_ID_PREFIXES):
        return False
    return not is_vex_suppressed_node_attributes(attributes)


def counts_as_finding_node(node: Any) -> bool:
    return counts_as_finding(
        entity_type=getattr(node, "entity_type", ""),
        node_id=str(getattr(node, "id", "")),
        attributes=getattr(node, "attributes", None),
    )


def _json_text_sql(key: str, *, placeholder: str) -> str:
    if placeholder == "%s":
        return f"(attributes::jsonb ->> '{key}')"
    return f"json_extract(attributes, '$.{key}')"


def finding_severity_count_sql(*, placeholder: str = "?") -> tuple[str, list[Any]]:
    """WHERE fragment: a rated node that :func:`counts_as_finding`, for either driver.

    ``?`` selects SQLite JSON functions, ``%s`` Postgres ``jsonb`` operators.
    """
    types = ",".join(placeholder for _ in FINDING_ENTITY_VALUES)
    excluded = " AND ".join(f"id NOT LIKE {placeholder}" for _ in FINDING_COUNT_EXCLUDED_ID_PREFIXES)
    excluded_params = [f"{prefix}%" for prefix in FINDING_COUNT_EXCLUDED_ID_PREFIXES]
    statuses = sorted(SUPPRESSING_VEX_STATUSES)
    status_placeholders = ",".join(placeholder for _ in statuses)
    vex_status = _json_text_sql("vex_status", placeholder=placeholder)
    vex_source = _json_text_sql("vex_source", placeholder=placeholder)
    not_suppressed = f"NOT (COALESCE({vex_status}, '') IN ({status_placeholders}) AND COALESCE({vex_source}, '') <> 'discovered')"
    return (
        f"(severity <> '' AND entity_type IN ({types}) AND {excluded} AND {not_suppressed})",
        [*FINDING_ENTITY_VALUES, *excluded_params, *statuses],
    )


#: :func:`finding_severity_count_sql` for SQLite's ``?`` placeholder.
FINDING_SEVERITY_SQLITE: tuple[str, list[Any]] = finding_severity_count_sql()
