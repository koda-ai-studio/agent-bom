"""Leadership summary without a second score, ranking, ownership join or trend."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import partial
from typing import Any

import anyio.to_thread
from fastapi import Request

from agent_bom.api.request_tenant import require_request_tenant_id
from agent_bom.api.routes.compliance import get_compliance_summary
from agent_bom.api.routes.compliance_routes.reads import get_posture_scorecard
from agent_bom.api.routes.enterprise_routes.governance import get_trends
from agent_bom.api.routes.overview import get_overview
from agent_bom.demo_estate import demo_estate_enabled
from agent_bom.mcp_tools.graph import exposure_paths_for_tenant

DEFAULT_EXPOSURE_LIMIT = 5
EVIDENCE_BOUNDARY = (
    "This unsigned brief summarizes technical evidence, not compliance attestation or confirmed exploitation. "
    "Sources are read independently; scan history is scope-specific and must not be subtracted from the tenant-wide posture score. "
    "Recorded paths describe exposure; consult their reachability and completeness evidence before taking action. "
    "The signed compliance pack is a separate artifact with its own scope and verification requirements."
)


async def build_executive_brief(request: Request, *, limit: int = DEFAULT_EXPOSURE_LIMIT) -> dict[str, Any]:
    """Reuse the same tenant reads the dashboard and MCP surfaces use."""
    tenant_id = require_request_tenant_id(request)
    # Sequential reads keep peak memory and aggregate-store concurrency bounded.
    overview = await get_overview(request)
    posture = await get_posture_scorecard(request)
    compliance = await get_compliance_summary(request)
    history = await anyio.to_thread.run_sync(partial(get_trends, request, limit=2, days=None, scope_id=None))
    raw_paths = await exposure_paths_for_tenant(tenant_id=tenant_id, limit=limit, view="summary")
    paths = json.loads(raw_paths)
    available = isinstance(paths, dict) and "error" not in paths
    return {
        "schema_version": "v1",
        "document_type": "executive-brief",
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_data": demo_estate_enabled(),
        "posture": posture,
        "issues": overview["issue_counts"],
        # Preserve the canonical owner/SLA provenance rather than joining on CVE.
        "remediation_priorities": overview["top_risks"][:limit],
        "exposure_paths": paths if available else None,
        "exposure_status": "available" if available else "unavailable",
        "compliance": compliance,
        "scan_history": history,
        "scope": {
            "consistency": "independent_source_reads",
            "overview_generated_at": overview.get("generated_at"),
            "issue_count_window": overview["issue_counts"].get("window"),
            "latest_compliance_scan": compliance.get("latest_scan"),
            "exposure_scan_id": paths.get("scan_id") if available else None,
            "exposure_snapshot_generation": paths.get("snapshot_generation") if available else None,
            "requested_priority_limit": limit,
            "remediation_basis": "overview.top_risks",
            "exposure_basis": "graph.attack_path_queue_rank",
        },
        "links": {
            "evidence_pack": "/v1/compliance/report/pack",
            "verification_key": "/v1/compliance/verification-key",
            "findings": "/v1/findings",
            "exposure_paths": "/v1/graph/attack-paths",
        },
        "evidence_boundary": EVIDENCE_BOUNDARY,
    }
