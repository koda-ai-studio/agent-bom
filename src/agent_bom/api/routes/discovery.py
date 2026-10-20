"""Agent discovery API routes.

Endpoints:
    GET /v1/agents                    list discovered agents
    GET /v1/agents/{agent_name}       agent detail with blast radius
    GET /v1/agents/{agent_name}/lifecycle  lifecycle graph (React Flow)
    GET /v1/agents/mesh               mesh topology (React Flow)
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.agent_evidence import AgentEvidence, agent_evidence, clear_agent_evidence_cache, job_revision
from agent_bom.api.agent_findings import agent_scoped_blast_rows, estate_reach_names
from agent_bom.api.mcp_observation_store import MCPObservation, agent_observation_id, merge_observations
from agent_bom.api.models import JobStatus
from agent_bom.api.read_models import AgentsResponse, DiscoveryProvidersResponse, documented
from agent_bom.api.read_models import runtime_estate_b as rt
from agent_bom.api.stores import _get_fleet_store, _get_mcp_observation_store, _get_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.asset_provenance import agent_discovery_provenance, package_discovery_provenance, package_version_provenance
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.core.severity import normalize_severity
from agent_bom.display_names import agent_payload_display_name
from agent_bom.inventory import build_agents_from_inventory
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.security import (
    sanitize_command_args,
    sanitize_env_vars,
    sanitize_error,
    sanitize_security_warnings,
    sanitize_text,
    sanitize_url,
)

if TYPE_CHECKING:
    from agent_bom.models import Agent

router = APIRouter()
_logger = logging.getLogger(__name__)
_AGENTS_RESPONSE_CACHE_TTL_SECONDS = 30.0
# tenant -> (completed-at monotonic stamp, job revision at build start, response)
_agents_response_cache: dict[str, tuple[float, str | None, dict[str, Any]]] = {}


def _clear_agents_response_cache_for_tests() -> None:
    _agents_response_cache.clear()
    clear_agent_evidence_cache()


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _discover_agents_with_demo_fallback() -> list[Any]:
    """Use curated agents in demo mode and host discovery in real deployments."""
    from agent_bom.demo_estate.bootstrap import demo_estate_enabled

    if not demo_estate_enabled():
        from agent_bom.discovery import discover_all

        return discover_all()

    from agent_bom.demo import DEMO_INVENTORY

    return build_agents_from_inventory(DEMO_INVENTORY, "agent-bom --demo")


def _host_agents_for_tenant(tenant_id: str) -> list[Any] | None:
    """Live host agents when this tenant may see them, else ``None``.

    The API host's own AI clients are not a tenant's estate. Live discovery is
    served only to the showcase tenant in demo mode, or when an operator bound
    this host to the tenant (the same fail-closed gate the scan pipeline
    enforces for ``discover_host``).
    ``None`` tells callers to serve the tenant's scanned estate instead.
    """
    from agent_bom.api.scan_boundary import require_host_discovery_for_tenant
    from agent_bom.demo_estate.bootstrap import SHOWCASE_TENANT, demo_estate_enabled
    from agent_bom.security import SecurityError

    if demo_estate_enabled():
        if tenant_id != SHOWCASE_TENANT:
            return None
    else:
        try:
            require_host_discovery_for_tenant(tenant_id)
        except SecurityError:
            return None
    return _discover_agents_with_demo_fallback()


def _scanned_estate_agents(tenant_id: str) -> list[dict[str, Any]]:
    return [_named(agent) for agent in deepcopy(_agent_evidence(tenant_id).estate_agents)]


def _named(agent: dict[str, Any]) -> dict[str, Any]:
    agent["display_name"] = agent_payload_display_name(agent)
    return agent


def _merge_strings(*values: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in values:
        for value in group:
            if value not in seen:
                seen.add(value)
                merged.append(value)
    return merged


def _merge_security_intelligence(*values: list[dict[str, object]]) -> list[dict[str, object]]:
    merged: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for group in values:
        for item in group:
            if not isinstance(item, dict):
                continue
            safe_item = sanitize_security_intelligence_entry(item)
            key = (str(safe_item.get("entry_id") or ""), str(safe_item.get("matched_value") or ""))
            if key in seen:
                continue
            seen.add(key)
            merged.append(safe_item)
    return merged


def _agent_evidence(tenant_id: str) -> AgentEvidence:
    return agent_evidence(_get_store(), tenant_id)


def _observation_ids(agent: Any, server: Any, fleet_agent: dict[str, Any] | None = None) -> tuple[str, None]:
    # A legacy name-derived record cannot establish membership, even when the
    # name happens to be unique today. Keep it unbound until recollected.
    subject = str((fleet_agent or {}).get("agent_id") or agent.canonical_id)
    return agent_observation_id(subject, server.canonical_id), None


def _agent_count_by_class(agents: Iterable[Agent]) -> dict[str, int]:
    """Split discovered agents into AI clients vs background agents (additive).

    Excludes synthetic SBOM/image wrappers. Lets clients render one authoritative
    breakdown instead of each re-deriving from ``agent_type``.
    """
    from agent_bom.models import classify_agent_kind

    counts = {"client": 0, "background": 0}
    for agent in agents:
        kind = classify_agent_kind(agent)
        if kind in counts:
            counts[kind] += 1
    return counts


def _auth_mode(server: Any) -> str:
    """Declared auth mode, else the mode the server's config evidences."""
    declared = getattr(server, "auth_mode", None)
    if declared is not None:
        return str(declared)
    server_url = getattr(server, "url", None)
    if getattr(server, "credential_names", None):
        return "env-credentials"
    if server_url and "@" in server_url:
        return "url-embedded-credentials"
    return "network-no-auth-observed" if server_url else "local-stdio"


def _serialize_agent(
    agent: Agent,
    *,
    fleet_agent: dict[str, Any] | None = None,
    scan_history_index: dict[tuple[str, str], dict[str, Any]] | None = None,
    gateway_index: dict[tuple[str, str], dict[str, Any]] | None = None,
    observation_index: dict[str, MCPObservation] | None = None,
) -> dict:
    payload = asdict(agent)
    payload["display_name"] = agent_payload_display_name(payload)
    payload["canonical_id"] = agent.canonical_id
    payload["stable_id"] = agent.stable_id
    # Display-only class (AI client/host vs background/framework agent). Additive field; never renames agent_type or any existing key.
    from agent_bom.models import classify_agent_kind

    payload["agent_class"] = classify_agent_kind(agent)
    agent_provenance = agent_discovery_provenance(agent)
    payload["discovery_provenance"] = agent_provenance
    payload["mcp_servers"] = []
    for server in agent.mcp_servers:
        server_payload = asdict(server)
        credential_names = list(getattr(server, "credential_names", []) or [])
        server_url = getattr(server, "url", None)
        auth_mode = _auth_mode(server)
        has_credentials = getattr(server, "has_credentials", None)
        if has_credentials is None:
            has_credentials = bool(credential_names)

        server_payload["auth_mode"] = auth_mode
        server_payload["has_credentials"] = has_credentials
        server_payload["command"] = sanitize_text(getattr(server, "command", ""), max_len=200)
        server_payload["env"] = sanitize_env_vars(dict(getattr(server, "env", {}) or {}))
        server_payload["credential_env_vars"] = credential_names
        server_payload["security_blocked"] = bool(getattr(server, "security_blocked", False))
        server_payload["args"] = sanitize_command_args(list(getattr(server, "args", []) or []))
        server_payload["url"] = sanitize_url(server_url)
        server_payload.setdefault("config_path", getattr(server, "config_path", None))
        server_payload["security_warnings"] = sanitize_security_warnings(list(getattr(server, "security_warnings", []) or []))
        server_payload["security_intelligence"] = _merge_security_intelligence(list(getattr(server, "security_intelligence", []) or []))
        for idx, package in enumerate(getattr(server, "packages", []) or []):
            if idx < len(server_payload.get("packages", []) or []):
                server_payload["packages"][idx]["version_provenance"] = package_version_provenance(
                    package,
                    inherited=agent_provenance,
                )
                server_payload["packages"][idx]["discovery_provenance"] = package_discovery_provenance(
                    package,
                    inherited=agent_provenance,
                )
        observation_id, legacy_observation_id = _observation_ids(agent, server, fleet_agent)
        stored_observation = (observation_index or {}).get(observation_id)
        if stored_observation is None and legacy_observation_id:
            stored_observation = (observation_index or {}).get(legacy_observation_id)
        scan_history = (scan_history_index or {}).get(
            (agent.canonical_id, server.canonical_id),
            {"present": False, "scan_sources": [], "first_seen": None, "last_seen": None},
        )
        gateway_state = (gateway_index or {}).get(
            (agent.canonical_id, server.canonical_id),
            {"gateway_registered": False, "source_agents": []},
        )
        observed_via = ["local_discovery"]
        observed_scopes = ["endpoint"]
        if scan_history["present"]:
            observed_via.append("scan_result")
            observed_scopes.append("scan")
        if fleet_agent is not None:
            observed_via.append("fleet_sync")
        if gateway_state["gateway_registered"]:
            observed_via.append("gateway_discovery")
            observed_scopes.append("gateway")
        if stored_observation is not None:
            server_payload["security_blocked"] = bool(server_payload["security_blocked"]) or stored_observation.security_blocked
            server_payload["security_warnings"] = _merge_strings(
                list(server_payload.get("security_warnings", []) or []),
                sanitize_security_warnings(stored_observation.security_warnings),
            )
            server_payload["security_intelligence"] = _merge_security_intelligence(
                list(server_payload.get("security_intelligence", []) or []),
                stored_observation.security_intelligence,
            )
            observed_via = sorted(set(stored_observation.observed_via) | set(observed_via))
            observed_scopes = sorted(set(stored_observation.observed_scopes) | set(observed_scopes))
            scan_sources = sorted(set(stored_observation.scan_sources) | set(scan_history["scan_sources"]))
            source_agents = sorted(set(stored_observation.source_agents) | set(gateway_state["source_agents"]))
            configured_locally = stored_observation.configured_locally
            fleet_present = stored_observation.fleet_present or fleet_agent is not None
            gateway_registered = stored_observation.gateway_registered or gateway_state["gateway_registered"]
            runtime_observed = stored_observation.runtime_observed
            first_seen = stored_observation.first_seen or scan_history["first_seen"]
            last_seen = stored_observation.last_seen or (fleet_agent.get("last_discovery") if fleet_agent else scan_history["last_seen"])
            last_synced = stored_observation.last_synced or (fleet_agent.get("updated_at") if fleet_agent else None)
        else:
            scan_sources = list(scan_history["scan_sources"])
            source_agents = list(gateway_state["source_agents"])
            configured_locally = True
            fleet_present = fleet_agent is not None
            gateway_registered = gateway_state["gateway_registered"]
            runtime_observed = False
            first_seen = scan_history["first_seen"]
            last_seen = fleet_agent.get("last_discovery") if fleet_agent else scan_history["last_seen"]
            last_synced = fleet_agent.get("updated_at") if fleet_agent else None
        payload["mcp_servers"].append(server_payload)
        server_payload["provenance"] = {
            "observed_via": observed_via,
            "observed_scopes": observed_scopes,
            "scan_sources": scan_sources,
            "source_agents": source_agents,
            "configured_locally": configured_locally,
            "fleet_present": fleet_present,
            "gateway_registered": gateway_registered,
            # Runtime correlation for per-server MCP objects is not yet wired through
            # a canonical store. Keep this explicit instead of inferring from alert volume.
            "runtime_observed": runtime_observed,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "last_synced": last_synced,
        }
    return payload


def _observation_index(tenant_id: str) -> dict[str, MCPObservation]:
    return {row.observation_id: row for row in _get_mcp_observation_store().list_by_tenant(tenant_id)}


def _live_observation_index(
    tenant_id: str,
    agents: list[Any],
    fleet_index: dict[str, dict[str, Any]],
    scan_history_index: dict[tuple[str, str], dict[str, Any]],
    gateway_index: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, MCPObservation]:
    """Stored observations with live discovery merged in memory only.

    Read routes never persist: stored rows stay owned by explicit writers
    (fleet sync, scans), so a GET cannot write into the caller's tenant.
    """
    index = _observation_index(tenant_id)
    for agent in agents:
        fleet_agent = fleet_index.get(getattr(agent, "canonical_id", ""))
        _overlay_agent_observations(tenant_id, agent, fleet_agent, scan_history_index, gateway_index, index)
    return index


def _overlay_agent_observations(
    tenant_id: str,
    agent: Any,
    fleet_agent: dict[str, Any] | None,
    scan_history_index: dict[tuple[str, str], dict[str, Any]],
    gateway_index: dict[tuple[str, str], dict[str, Any]],
    observation_index: dict[str, MCPObservation],
) -> None:
    for server in agent.mcp_servers:
        server_url = getattr(server, "url", None)
        scan_history = scan_history_index.get(
            (agent.canonical_id, server.canonical_id),
            {"present": False, "scan_sources": [], "first_seen": None, "last_seen": None},
        )
        gateway_state = gateway_index.get(
            (agent.canonical_id, server.canonical_id),
            {"gateway_registered": False, "source_agents": []},
        )
        observed_via = ["local_discovery"]
        observed_scopes = ["endpoint"]
        if scan_history["present"]:
            observed_via.append("scan_result")
            observed_scopes.append("scan")
        if fleet_agent is not None:
            observed_via.append("fleet_sync")
        if gateway_state["gateway_registered"]:
            observed_via.append("gateway_discovery")
            observed_scopes.append("gateway")
        credential_names = list(getattr(server, "credential_names", []) or [])
        auth_mode = _auth_mode(server)
        observation_id, legacy_observation_id = _observation_ids(agent, server, fleet_agent)
        candidate = MCPObservation(
            tenant_id=tenant_id,
            observation_id=observation_id,
            server_stable_id=getattr(server, "stable_id", server.name),
            server_fingerprint=getattr(server, "fingerprint", ""),
            server_name=server.name,
            agent_name=agent.name,
            agent_id=str((fleet_agent or {}).get("agent_id") or ""),
            agent_canonical_id=agent.canonical_id,
            transport=getattr(getattr(server, "transport", ""), "value", getattr(server, "transport", "")) or "",
            url=sanitize_url(server_url),
            auth_mode=auth_mode,
            command=sanitize_text(getattr(server, "command", ""), max_len=200),
            args=sanitize_command_args(list(getattr(server, "args", []) or [])),
            config_path=getattr(server, "config_path", None),
            credential_env_vars=credential_names,
            security_blocked=bool(getattr(server, "security_blocked", False)),
            security_warnings=sanitize_security_warnings(list(getattr(server, "security_warnings", []) or [])),
            security_intelligence=[
                sanitize_security_intelligence_entry(item)
                for item in (getattr(server, "security_intelligence", []) or [])
                if isinstance(item, dict)
            ],
            observed_via=observed_via,
            observed_scopes=observed_scopes,
            scan_sources=list(scan_history["scan_sources"]),
            source_agents=list(gateway_state["source_agents"]),
            configured_locally=True,
            fleet_present=fleet_agent is not None,
            gateway_registered=gateway_state["gateway_registered"],
            runtime_observed=False,
            first_seen=scan_history["first_seen"],
            last_seen=fleet_agent.get("last_discovery") if fleet_agent else scan_history["last_seen"],
            last_synced=fleet_agent.get("updated_at") if fleet_agent else None,
        )
        existing = observation_index.get(observation_id)
        if existing is None and legacy_observation_id:
            existing = observation_index.get(legacy_observation_id)
        observation_index[observation_id] = merge_observations(existing, candidate)


def _fleet_identity_index(tenant_id: str) -> dict[str, dict[str, Any]]:
    fleet_groups: dict[str, list[Any]] = {}
    for item in _get_fleet_store().list_by_tenant(tenant_id):
        if item.canonical_id:
            fleet_groups.setdefault(item.canonical_id, []).append(item)
    return {key: rows[0].model_dump() for key, rows in fleet_groups.items() if len(rows) == 1}


def _build_agents_response(tenant_id: str) -> dict[str, Any]:
    from agent_bom.api.estate_agents import AGENT_COUNT_DEFINITION, count_agent_payloads_by_class
    from agent_bom.parsers import extract_packages

    host_agents = _host_agents_for_tenant(tenant_id)
    if host_agents is None:
        estate = _scanned_estate_agents(tenant_id)
        return {
            "scope": "scanned_estate",
            "source": (
                "Agents from this tenant's completed scans, one row per canonical agent identity "
                "(the same population as /v1/inventory). Live discovery of this API host's own "
                "AI-client configs is disabled unless an operator binds the host to this tenant."
            ),
            "count_definition": AGENT_COUNT_DEFINITION,
            "agents": estate,
            "count": len(estate),
            "count_by_class": count_agent_payloads_by_class(estate),
            "warnings": [],
        }
    agents = host_agents
    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)
    evidence = _agent_evidence(tenant_id)
    scan_history_index = evidence.scan_history
    gateway_index = evidence.gateway
    # Only unique canonical identities bind discovery to fleet state. Names
    # remain labels, including for legacy rows lacking identity evidence.
    fleet_index = _fleet_identity_index(tenant_id)
    observation_index = _live_observation_index(tenant_id, agents, fleet_index, scan_history_index, gateway_index)

    return {
        # Scope marker so callers never conflate this population with the
        # scanned-estate roll-up at /v1/inventory. This endpoint is live
        # local-disk discovery of AI-client configs on this host (no CVE scan);
        # /v1/inventory aggregates agents from completed scan jobs (the estate).
        "scope": "local_discovery",
        "source": (
            "Live local-disk discovery of AI-client agent configs on this host "
            "(no CVE scan). For scanned-estate agents aggregated from completed "
            "scan jobs, see /v1/inventory."
        ),
        "agents": [
            _serialize_agent(
                a,
                fleet_agent=fleet_index.get(getattr(a, "canonical_id", "")),
                scan_history_index=scan_history_index,
                gateway_index=gateway_index,
                observation_index=observation_index,
            )
            for a in agents
        ],
        "count": len(agents),
        "count_by_class": _agent_count_by_class(agents),
        "warnings": [],
    }


def _cached_agents_response(tenant_id: str) -> dict[str, Any] | None:
    """A cached response while the TTL holds and no scan has landed since its build."""
    cached = _agents_response_cache.get(tenant_id)
    if cached is None or time.monotonic() - cached[0] > _AGENTS_RESPONSE_CACHE_TTL_SECONDS:
        return None
    if cached[1] != job_revision(_get_store(), tenant_id):
        return None
    return deepcopy(cached[2])


def _build_and_cache_agents_response(tenant_id: str) -> dict[str, Any]:
    revision = job_revision(_get_store(), tenant_id)
    response = _build_agents_response(tenant_id)
    # Stamp when the build finishes: a build longer than the TTL is still served.
    _agents_response_cache[tenant_id] = (time.monotonic(), revision, deepcopy(response))
    return response


@router.get("/agents", **documented(AgentsResponse), tags=["discovery"])
async def list_agents(
    request: Request,
    refresh: bool = Query(False, description="Bypass the sidebar cache and perform live local discovery"),
) -> dict:
    """Quick auto-discovery of local AI agent configs (Claude Desktop, Cursor, Windsurf...).
    No CVE scan — instant results for the UI sidebar.
    """
    try:
        tenant_id = _tenant_id(request)
        if not refresh:
            cached = await anyio.to_thread.run_sync(_cached_agents_response, tenant_id)
            if cached is not None:
                return cached
        async with adaptive_backpressure("discovery"):
            return await anyio.to_thread.run_sync(_build_and_cache_agents_response, tenant_id)
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Agent discovery failed: %s", sanitize_text(sanitize_error(exc, generic=True)))
        raise HTTPException(status_code=500, detail=sanitize_error(exc, generic=True)) from exc


@router.get("/discovery/providers", **documented(DiscoveryProvidersResponse), tags=["discovery"])
def list_discovery_providers() -> dict:
    """Return registered discovery provider capability and trust contracts."""

    from agent_bom.cloud import provider_contracts

    return provider_contracts()


@router.get("/agents/mesh", **documented(rt.AgentMeshResponse), tags=["discovery"], deprecated=True)
async def get_agent_mesh(request: Request) -> dict:
    """Get a ReactFlow-compatible mesh topology of all discovered agents.

    Shows agents, their MCP servers, tools, and vulnerability overlay
    as an interactive graph.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).

    The synchronous discovery + store scans run in a worker thread so they
    never block the event loop.
    """
    try:
        return await anyio.to_thread.run_sync(_get_agent_mesh_impl, request)
    except Exception as exc:  # noqa: BLE001
        _logger.error("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


def _get_agent_mesh_impl(request: Request) -> dict:
    from agent_bom.output.agent_mesh import build_agent_mesh
    from agent_bom.parsers import extract_packages

    tenant_id = _tenant_id(request)
    host_agents = _host_agents_for_tenant(tenant_id)
    if host_agents is None:
        estate_blast: list[dict] = []
        for job in _get_store().list_all(tenant_id=tenant_id):
            if job.status == JobStatus.DONE and job.result:
                estate_blast.extend(job.result.get("blast_radius", []))
        return build_agent_mesh(_scanned_estate_agents(tenant_id), estate_blast)
    agents = host_agents
    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)

    evidence = _agent_evidence(tenant_id)
    scan_history_index = evidence.scan_history
    gateway_index = evidence.gateway
    fleet_index = _fleet_identity_index(tenant_id)
    observation_index = _live_observation_index(tenant_id, agents, fleet_index, scan_history_index, gateway_index)
    agents_data = [
        _serialize_agent(
            a,
            fleet_agent=fleet_index.get(getattr(a, "canonical_id", "")),
            scan_history_index=scan_history_index,
            gateway_index=gateway_index,
            observation_index=observation_index,
        )
        for a in agents
    ]

    # Gather blast radius from completed scans for vuln overlay.
    all_blast: list[dict] = []
    for job in _get_store().list_all(tenant_id=_tenant_id(request)):
        if job.status == JobStatus.DONE and job.result:
            all_blast.extend(job.result.get("blast_radius", []))

    return build_agent_mesh(agents_data, all_blast)


@router.get("/agents/{agent_name}", **documented(rt.AgentDetailResponse), tags=["discovery"])
async def get_agent_detail(request: Request, agent_name: str) -> dict:
    """Get detailed view of a single agent with cross-referenced scan data.

    The synchronous discovery + store scans run in a worker thread so they
    never block the event loop.
    """
    try:
        return await anyio.to_thread.run_sync(_get_agent_detail_impl, request, agent_name)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _logger.error("Agent detail failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


def _get_agent_detail_impl(request: Request, agent_name: str) -> dict:
    from agent_bom.parsers import extract_packages

    host_agents = _host_agents_for_tenant(_tenant_id(request))
    if host_agents is None:
        return _estate_agent_detail(request, agent_name)
    agents = host_agents
    matches = [a for a in agents if a.canonical_id == agent_name]
    if not matches:
        # Compatibility for display-name URLs: resolve the selection only;
        # evidence joins below still require the selected object's identity.
        matches = [a for a in agents if a.name == agent_name]
    if len(matches) > 1:
        raise HTTPException(status_code=409, detail="Ambiguous agent label; select its canonical ID")
    if not matches:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = matches[0]

    for server in agent.mcp_servers:
        if not server.packages:
            server.packages = extract_packages(server)

    total_packages = sum(len(s.packages) for s in agent.mcp_servers)
    total_tools = sum(len(s.tools) for s in agent.mcp_servers)
    all_credentials: list[str] = []
    for s in agent.mcp_servers:
        all_credentials.extend(s.credential_names)

    tenant_id = _tenant_id(request)
    evidence = _agent_evidence(tenant_id)
    agent_blast = deepcopy(
        agent_scoped_blast_rows(
            evidence.blast_rows(agent.canonical_id),
            agent_id=agent.canonical_id,
            credential_names=set(all_credentials),
            tool_names={tool.name for s in agent.mcp_servers for tool in s.tools},
            server_names={s.name for s in agent.mcp_servers},
        )
    )

    # Every blast radius lands in exactly one bucket. Advisories with no CVSS
    # vector normalise to ``unknown``; without an explicit bucket they fell out
    # of the histogram entirely and the detail page rendered "N vulnerabilities"
    # beside a 0/0/0/0 strip labelled Clean.
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0}
    for br in agent_blast:
        sev = normalize_severity(br.get("severity"))
        severity_counts[sev if sev in severity_counts else "unrated"] += 1

    fleet_index = _fleet_identity_index(tenant_id)
    fleet_agent = fleet_index.get(agent.canonical_id)
    scan_history_index = evidence.scan_history
    gateway_index = evidence.gateway
    observation_index = _live_observation_index(tenant_id, [agent], fleet_index, scan_history_index, gateway_index)

    return {
        "agent": _serialize_agent(
            agent,
            fleet_agent=fleet_agent,
            scan_history_index=scan_history_index,
            gateway_index=gateway_index,
            observation_index=observation_index,
        ),
        "summary": {
            "total_servers": len(agent.mcp_servers),
            "total_packages": total_packages,
            "total_tools": total_tools,
            "total_credentials": len(all_credentials),
            "total_vulnerabilities": len(agent_blast),
            "severity_breakdown": severity_counts,
        },
        "blast_radius": agent_blast,
        "credentials": all_credentials,
        "fleet": fleet_agent,
    }


def _estate_agent_detail(request: Request, agent_name: str) -> dict:
    """Agent detail from the tenant's scanned estate (host discovery disabled)."""
    from agent_bom.api.estate_agents import agent_identity_key

    tenant_id = _tenant_id(request)
    evidence = _agent_evidence(tenant_id)
    estate = evidence.estate_agents
    matches = [agent for agent in estate if agent_identity_key(agent) == agent_name]
    if not matches:
        matches = [agent for agent in estate if agent.get("name") == agent_name]
        identities = {agent_identity_key(agent) for agent in matches}
        if len(matches) > 1 and (len(identities) > 1 or None in identities):
            raise HTTPException(status_code=409, detail="Ambiguous agent label; select its canonical ID")
    if not matches:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = _named(deepcopy(matches[0]))
    canonical_id = agent_identity_key(agent) or ""

    servers = [server for server in agent.get("mcp_servers") or [] if isinstance(server, dict)]
    credentials: list[str] = []
    for server in servers:
        for name in server.get("credential_env_vars") or []:
            if isinstance(name, str) and name not in credentials:
                credentials.append(name)
    reach = estate_reach_names(servers, credentials)
    agent_blast = deepcopy(agent_scoped_blast_rows(evidence.blast_rows(canonical_id), agent_id=canonical_id, **reach))
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0}
    for br in agent_blast:
        sev = normalize_severity(br.get("severity"))
        severity_counts[sev if sev in severity_counts else "unrated"] += 1

    return {
        "agent": agent,
        "summary": {
            "total_servers": len(servers),
            "total_packages": sum(len(server.get("packages") or []) for server in servers),
            "total_tools": sum(len(server.get("tools") or []) for server in servers),
            "total_credentials": len(credentials),
            "total_vulnerabilities": len(agent_blast),
            "severity_breakdown": severity_counts,
        },
        "blast_radius": agent_blast,
        "credentials": credentials,
        "fleet": _fleet_identity_index(tenant_id).get(canonical_id),
    }


@router.get("/agents/{agent_name}/lifecycle", **documented(rt.AgentLifecycleResponse), tags=["discovery"])
async def get_agent_lifecycle(request: Request, agent_name: str) -> dict:
    """Get React Flow nodes/edges for an agent's full lifecycle graph.

    Shows: Agent -> MCP Servers -> Tools/Credentials -> Packages -> CVEs
    """
    from agent_bom.graph.lifecycle import agent_lifecycle_view

    detail = await get_agent_detail(request, agent_name)
    return agent_lifecycle_view(detail["agent"], tenant_id=_tenant_id(request), blast_radius=detail.get("blast_radius") or [])
