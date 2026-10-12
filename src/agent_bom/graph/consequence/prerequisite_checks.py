"""Occurrence-bound collected facts versus still-unobserved local prerequisites."""

from agent_bom.graph.consequence.contracts import PrerequisiteCheck
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode


def collected_checks(vulnerability: UnifiedNode, links: list[UnifiedEdge]) -> list[PrerequisiteCheck]:
    checks = [PrerequisiteCheck(name="affected_inventory", status="recorded", basis="inventory", evidence_refs=[e.id for e in links])]
    versions = {str(e.evidence.get("package_version") or e.evidence.get("version") or "").strip() for e in links}
    versions.discard("")
    exact = len(versions) == 1 and not versions.intersection({"unknown", "latest", "*"})
    checks.append(
        PrerequisiteCheck(
            name="recorded_version",
            status="recorded" if exact else "missing",
            basis="inventory",
            value=next(iter(versions)) if exact else None,
            evidence_refs=[e.id for e in links] if exact else [],
        )
    )
    for key, name in (
        ("attack_vector", "required_entry_vector"),
        ("attack_complexity", "required_complexity"),
        ("privileges_required", "required_privileges"),
        ("user_interaction", "required_interaction"),
    ):
        value = vulnerability.attributes.get(key)
        present = isinstance(value, str) and bool(value.strip()) and len(value) <= 160
        checks.append(
            PrerequisiteCheck(
                name=name,
                status="recorded" if present else "missing",
                basis="advisory",
                value=value if present else None,
                evidence_refs=[vulnerability.id] if present else [],
            )
        )
    for name in ("deployed_configuration", "entry_point", "local_exploitation"):
        checks.append(PrerequisiteCheck(name=name, status="missing", basis="local"))
    return checks
