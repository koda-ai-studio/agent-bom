"""Tenant-scoped scan evidence exports and remediation reads."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, cast

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from agent_bom.api import time_window
from agent_bom.api.finding_snapshot_read import current_findings_snapshot
from agent_bom.api.models import JobStatus
from agent_bom.api.read_models import documented
from agent_bom.api.read_models.scan import ScanLicensesResponse, ScanVexResponse
from agent_bom.api.remediation_view import CurrentRemediationResponse
from agent_bom.api.scan_graph_view import _context_graph_payload as _context_graph_payload
from agent_bom.api.scan_graph_view import _graph_export_response as _graph_export_response
from agent_bom.api.scan_graph_view import _scan_graph_compute_call as _scan_graph_compute_call
from agent_bom.api.scan_request_context import _load_job_for_request, _tenant_id
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.evidence.agent_bom import AgentBomDocument
from agent_bom.evidence.scan_agent_bom import AgentSelectionError, build_scan_agent_bom
from agent_bom.rbac import require_authenticated_permission

router = APIRouter()


@router.get("/scan/{job_id}/attack-flow", tags=["scan"])
async def get_attack_flow(
    request: Request,
    job_id: str,
    cve: str | None = None,
    severity: str | None = None,
    framework: str | None = None,
    agent: str | None = None,
) -> dict:
    """Get the attack flow graph for a completed scan.

    Returns React Flow-compatible nodes/edges showing the CVE -> package ->
    server -> agent attack chain with credential and tool branches.

    Query params for filtering:
      ?cve=CVE-2025-xxx     - show only this CVE's blast radius
      ?severity=critical     - filter by severity level
      ?framework=LLM03       - filter by OWASP/ATLAS/NIST tag
      ?agent=claude-desktop  - filter to a specific agent
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    from agent_bom.output.attack_flow import build_attack_flow

    blast_radius = job.result.get("blast_radius", [])
    agents_data = job.result.get("agents", [])

    payload = build_attack_flow(
        blast_radius,
        agents_data,
        cve=cve,
        severity=severity,
        framework=framework,
        agent_name=agent,
    )
    from agent_bom.output.interop_security import sanitize_linked_document

    return sanitize_linked_document(payload)


@router.get("/scan/{job_id}/context-graph", tags=["scan"])
async def get_context_graph(request: Request, job_id: str, agent: str | None = None) -> dict:
    """Get the agent context graph with lateral movement analysis.

    Returns nodes, edges, lateral paths, interaction risks, and stats for
    a completed scan.  Optionally filter lateral paths to a single agent.

    Query params:
      ?agent=claude-desktop  - only compute lateral paths from this agent
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    tenant_id = str(getattr(request.state, "tenant_id", "") or "")
    return cast(
        dict,
        await _scan_graph_compute_call(_context_graph_payload, job.result, agent=agent, scan_id=job.job_id, tenant_id=tenant_id),
    )


@router.get("/scan/{job_id}/graph-export", tags=["scan"], response_model=None)
async def get_graph_export(
    request: Request,
    job_id: str,
    format: str = "json",
    mermaid_limit: Annotated[
        int,
        Query(
            ge=0,
            le=5000,
            description="Maximum nodes rendered for Mermaid output; 0 renders the full graph.",
        ),
    ] = 80,
) -> dict | str | PlainTextResponse:
    """Export the dependency graph in graph-native formats.

    Query params:
      ?format=json      JSON nodes/edges (default)
      ?format=dot       Graphviz DOT
      ?format=mermaid   Mermaid flowchart
      ?format=graphml   GraphML with AIBOM attributes (yEd/Gephi/NetworkX)
      ?format=cypher    Neo4j Cypher import script
      ?mermaid_limit=80 Maximum nodes rendered for Mermaid; 0 renders all
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    result = job.result if isinstance(job.result, dict) else {}
    return cast(
        "dict | str | PlainTextResponse",
        await _scan_graph_compute_call(
            _graph_export_response,
            result,
            format=format,
            mermaid_limit=mermaid_limit,
            scan_id=job.job_id,
            tenant_id=_tenant_id(request),
        ),
    )


@router.get(
    "/scan/{job_id}/agent-bom",
    tags=["scan"],
    response_model=AgentBomDocument,
    dependencies=[cast(Any, require_authenticated_permission("read"))],
)
async def get_scan_agent_bom(
    request: Request,
    job_id: str,
    agent_id: Annotated[str, Query(min_length=1, max_length=512)],
) -> AgentBomDocument:
    """Export one exact recorded agent's composition with its source-scan receipt.

    Inherits authenticated scan-read tenancy. Explicit local no-auth mode is
    the existing development exception. Labels never resolve identity; missing
    or conflicting identity fails closed. No discovery or provider calls run.
    Findings and runtime/authority assessments remain separate scan evidence.
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not isinstance(job.result, dict):
        raise HTTPException(status_code=409, detail="A completed scan result is required")
    try:
        return cast(
            AgentBomDocument,
            await _scan_graph_compute_call(
                build_scan_agent_bom,
                job.result,
                agent_id=agent_id,
                tenant_id=require_request_tenant_id(request),
                scan_id=job.job_id,
            ),
        )
    except AgentSelectionError as exc:
        raise HTTPException(status_code=409, detail="Agent identity is unavailable or ambiguous in this scan") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Scan composition is invalid, unsupported, or exceeds export limits") from exc


@router.get("/findings/remediation", tags=["scan"], response_model=CurrentRemediationResponse)
async def get_current_remediation(request: Request) -> CurrentRemediationResponse:
    """Package upgrade actions from the tenant's current findings across targets."""
    from agent_bom.api.remediation_view import current_remediation_response, remediation_finding_projection

    snapshot = await asyncio.to_thread(
        current_findings_snapshot,
        request,
        max_findings=10_000,
        window_days=None,
        project_graph_reachability=False,
        row_projection=remediation_finding_projection,
    )
    window = time_window.window_metadata(time_window.normalize_window_days(None))
    return current_remediation_response(snapshot, window)


@router.get("/scan/{job_id}/remediation", tags=["scan"])
async def get_remediation_plan(request: Request, job_id: str) -> dict:
    """Return package upgrade actions without transferring the full scan report.

    One entry per package, with an explicit total for the client.
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")
    plan = job.result.get("remediation_plan") or [] if isinstance(job.result, dict) else []
    return {"job_id": job_id, "remediation_plan": plan, "total": len(plan)}


@router.get("/scan/{job_id}/licenses", **documented(ScanLicensesResponse), tags=["scan"])
async def get_licenses(request: Request, job_id: str) -> dict:
    """Return a completed scan's license findings, coverage, status and categories."""
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    # If the scan already computed license_report, return it
    if isinstance(job.result, dict) and job.result.get("license_report"):
        return cast(dict, job.result["license_report"])

    # Otherwise compute on-the-fly from scan result agents
    from agent_bom.license_policy import evaluate_license_policy as _eval_lic
    from agent_bom.license_policy import to_serializable as _lic_ser
    from agent_bom.models import Agent as _AgentModel
    from agent_bom.models import AgentType as _AgentType
    from agent_bom.models import MCPServer as _ServerModel
    from agent_bom.models import Package as _PkgModel

    agents_data = job.result.get("agents", []) if isinstance(job.result, dict) else []
    model_agents = []
    for ad in agents_data:
        servers = []
        for sd in ad.get("mcp_servers", []):
            pkgs = [
                _PkgModel(
                    name=p.get("name", ""),
                    version=p.get("version", ""),
                    ecosystem=p.get("ecosystem", ""),
                    license=p.get("license"),
                    license_expression=p.get("license_expression"),
                )
                for p in sd.get("packages", [])
            ]
            servers.append(_ServerModel(name=sd.get("name", ""), command=sd.get("command", ""), packages=pkgs))
        model_agents.append(
            _AgentModel(name=ad.get("name", ""), agent_type=_AgentType(ad.get("type", "custom")), config_path="", mcp_servers=servers)
        )

    lic_report = _eval_lic(model_agents)
    return dict(_lic_ser(lic_report))


@router.get("/scan/{job_id}/vex", **documented(ScanVexResponse), tags=["scan"])
async def get_vex(request: Request, job_id: str) -> dict:
    """Get the VEX (Vulnerability Exploitability eXchange) document for a completed scan.

    Returns VEX statements with vulnerability status (affected, not_affected,
    fixed, under_investigation), justifications, and statistics.
    """
    job = await _load_job_for_request(request, job_id)
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    # Return pre-computed VEX data if available
    if isinstance(job.result, dict) and job.result.get("vex"):
        return cast(dict, job.result["vex"])

    # Otherwise generate on-the-fly from blast_radii
    return {"statements": [], "stats": {"total_statements": 0, "affected": 0, "not_affected": 0, "fixed": 0, "under_investigation": 0}}


@router.get("/scan/{job_id}/skill-audit", tags=["scan"])
async def get_skill_audit(request: Request, job_id: str) -> dict:
    """Get the skill security audit results for a completed scan.

    Returns findings from the skill file security audit including
    typosquat detection, unverified servers, shell access, and more.
    Empty results if no skill files were scanned.
    """
    job = await _load_job_for_request(request, job_id)

    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    return cast(
        dict,
        job.result.get(
            "skill_audit",
            {
                "findings": [],
                "packages_checked": 0,
                "servers_checked": 0,
                "credentials_checked": 0,
                "passed": True,
            },
        ),
    )
