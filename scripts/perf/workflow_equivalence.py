"""Exact equivalence for the workflow harness.

A stored finding must keep the same identity, source, time, scope and coverage
fields as the scanned one, through ingest, retry, update/delete, retention and
rebuild. The lifecycle view (``/v1/findings``) must keep finding ids and
``first_seen`` stable while ``last_seen`` only moves forward.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

FindingKey = tuple[str, str, str]

EQUIVALENCE_FIELDS: dict[str, tuple[str, ...]] = {
    "identity": ("canonical_id", "vulnerability_id", "package_name", "package_version", "package_stable_id", "ecosystem"),
    "source": ("primary_advisory_source", "advisory_sources", "severity_source"),
    "time": ("published_at", "modified_at"),
    "scope": ("affected_agents", "affected_servers", "affected_agent_ids", "asset"),
    "coverage": ("advisory_coverage_state",),
}


def _normalize(value: Any) -> Any:
    if isinstance(value, list):
        return sorted(json.dumps(item, sort_keys=True, default=str) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    return value


def finding_key(row: Mapping[str, Any]) -> FindingKey:
    package = row.get("package")
    name = row.get("package_name") or (package.get("name") if isinstance(package, dict) else package)
    version = row.get("package_version") or (package.get("version") if isinstance(package, dict) else None)
    return str(row.get("vulnerability_id")), str(name), str(version)


def finding_projections(rows: Iterable[Mapping[str, Any]]) -> dict[FindingKey, dict[str, Any]]:
    """Map each finding key to its normalized identity/source/time/scope/coverage fields."""
    out: dict[FindingKey, dict[str, Any]] = {}
    for row in rows:
        out[finding_key(row)] = {
            f"{group}.{field}": _normalize(row.get(field)) for group, fields in EQUIVALENCE_FIELDS.items() for field in fields
        }
    return dict(sorted(out.items()))


def projection_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    """Order-independent digest of every finding's identity/source/time/scope/coverage fields."""
    payload = [[list(key), fields] for key, fields in finding_projections(rows).items()]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _label(key: FindingKey) -> str:
    return "|".join(key)


def projection_mismatches(expected: Mapping[FindingKey, Mapping[str, Any]], actual: Mapping[FindingKey, Mapping[str, Any]]) -> list[str]:
    """Every missing, unexpected or changed finding field; empty when equivalent."""
    problems: list[str] = []
    for key in sorted(set(expected) | set(actual)):
        if key not in actual:
            problems.append(f"missing {_label(key)}")
        elif key not in expected:
            problems.append(f"unexpected {_label(key)}")
        else:
            problems += [f"changed {_label(key)} {field}" for field in expected[key] if expected[key][field] != actual[key].get(field)]
    return problems


def lifecycle_mismatches(before: Mapping[FindingKey, Mapping[str, Any]], after: Mapping[FindingKey, Mapping[str, Any]]) -> list[str]:
    """Findings present in both views must keep ``finding_id`` and ``first_seen``; ``last_seen`` never regresses."""
    problems: list[str] = []
    for key in sorted(set(before) & set(after)):
        old, new = before[key], after[key]
        for field in ("finding_id", "first_seen"):
            if old.get(field) != new.get(field):
                problems.append(f"{_label(key)} {field} {old.get(field)} -> {new.get(field)}")
        if str(new.get("last_seen") or "") < str(old.get("last_seen") or ""):
            problems.append(f"{_label(key)} last_seen went backwards")
    return problems


def _vulnerable_present(report: Mapping[str, Any], inventory: Mapping[str, Any]) -> list[tuple[FindingKey, list[str]]]:
    holders: dict[tuple[str, str], list[str]] = {}
    for agent in inventory["agents"]:
        for server in agent["mcp_servers"]:
            for package in server["packages"]:
                holders.setdefault((package["name"], package["version"]), []).append(agent["name"])
    rows = sorted({(row["vulnerability_id"], row["package_name"], row["package_version"]) for row in report["blast_radius"]})
    return [(key, sorted(set(holders[key[1:]]))) for key in rows if key[1:] in holders]


def mutate_inventory(report: Mapping[str, Any], inventory: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a copy of ``inventory`` with one vulnerable package removed and another added to one more agent.

    The first vulnerable package (sorted) is removed from every server, deleting its
    finding. The next one is added to the first agent that does not carry it,
    widening that finding's scope. Deterministic for a given input.
    """
    present = _vulnerable_present(report, inventory)
    if len(present) < 2:
        raise ValueError("the estate needs at least two vulnerable packages to mutate")
    (deleted, _), (widened, holders) = present[0], present[1]
    mutated = copy.deepcopy(dict(inventory))
    for agent in mutated["agents"]:
        for server in agent["mcp_servers"]:
            server["packages"] = [p for p in server["packages"] if (p["name"], p["version"]) != deleted[1:]]
    target = next(agent for agent in mutated["agents"] if agent["name"] not in holders and agent["mcp_servers"])
    ecosystem = next(
        p["ecosystem"]
        for agent in inventory["agents"]
        for server in agent["mcp_servers"]
        for p in server["packages"]
        if (p["name"], p["version"]) == widened[1:]
    )
    target["mcp_servers"][0]["packages"].append({"name": widened[1], "version": widened[2], "ecosystem": ecosystem})
    return mutated, {"deleted": deleted, "widened": widened, "added_agent": target["name"]}
