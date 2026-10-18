"""Server-side posture scorecard for a serialized (pushed) scan report.

A pushed report arrives as JSON, and its producer-supplied
``posture_scorecard`` is not trusted. This rebuilds exactly the report
attributes :func:`agent_bom.posture.compute_posture_scorecard` reads from the
retained evidence and runs that one computation, so a pushed scan and a
server-run scan of the same estate grade identically.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Mapping

from agent_bom.evidence.scan_run import serialized_coverage_view
from agent_bom.posture import PostureScorecard, compute_posture_scorecard


def _rows(value: Any) -> list[Mapping[str, Any]]:
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, list) else []


def _package_view(row: Mapping[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        name=str(row.get("name") or ""),
        version=str(row.get("version") or ""),
        ecosystem=str(row.get("ecosystem") or ""),
        purl=row.get("purl"),
        homepage=row.get("homepage"),
        repository_url=row.get("repository_url"),
        source_repo=row.get("source_repo"),
        scorecard_repo=row.get("scorecard_repo"),
        scorecard_score=row.get("scorecard_score"),
        scorecard_lookup_state=row.get("scorecard_lookup_state"),
        scorecard_lookup_reason=row.get("scorecard_lookup_reason"),
        vulnerability_count=len(_rows(row.get("vulnerabilities"))),
    )


def _server_view(row: Mapping[str, Any]) -> SimpleNamespace:
    credentials = [str(name) for name in row.get("credential_env_vars") or [] if name]
    return SimpleNamespace(
        has_credentials=bool(row.get("has_credentials")) or bool(credentials),
        credential_names=credentials,
        packages=[_package_view(pkg) for pkg in _rows(row.get("packages"))],
        registry_verified=bool(row.get("registry_verified")),
        tools=list(row.get("tools") or []),
        is_mcp_surface=str(row.get("surface") or "mcp-server") == "mcp-server",
    )


def _blast_radius_view(row: Mapping[str, Any]) -> SimpleNamespace:
    tags = {key: list(value or []) for key, value in row.items() if key.endswith("_tags") and isinstance(value, list)}
    compliance_tags = row.get("compliance_tags")
    vulnerability = SimpleNamespace(
        id=str(row.get("vulnerability_id") or row.get("id") or ""),
        severity=SimpleNamespace(value=str(row.get("severity") or "unknown").lower()),
        fixed_version=row.get("fixed_version"),
        is_kev=bool(row.get("is_kev") or row.get("cisa_kev")),
        epss_score=row.get("epss_score"),
        vex_status=row.get("vex_status"),
        vex_source=row.get("vex_source"),
        compliance_tags=compliance_tags if isinstance(compliance_tags, dict) else {},
    )
    return SimpleNamespace(vulnerability=vulnerability, suppressed=row.get("suppressed") is True, **tags)


def serialized_posture_report(result: Mapping[str, Any]) -> SimpleNamespace:
    """The :class:`AIBOMReport` surface the posture scorecard reads, from JSON."""
    view = serialized_coverage_view(dict(result))
    agents = [
        SimpleNamespace(mcp_servers=[_server_view(server) for server in _rows(agent.get("mcp_servers"))])
        for agent in _rows(result.get("agents"))
    ]
    servers = [server for agent in agents for server in agent.mcp_servers]
    view.agents = agents
    view.blast_radii = [_blast_radius_view(row) for row in _rows(result.get("blast_radius") or result.get("blast_radii"))]
    view.total_packages = sum(len(server.packages) for server in servers)
    view.total_vulnerabilities = sum(pkg.vulnerability_count for server in servers for pkg in server.packages)
    view.has_mcp_context = any(server.is_mcp_surface for server in servers)
    return view


def compute_posture_scorecard_from_result(result: Mapping[str, Any]) -> PostureScorecard:
    return compute_posture_scorecard(serialized_posture_report(result))  # type: ignore[arg-type]


__all__ = ["compute_posture_scorecard_from_result", "serialized_posture_report"]
