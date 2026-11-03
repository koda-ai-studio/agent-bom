"""Dashboard projection with separately pageable AST relationship evidence."""

from typing import Any
from urllib.parse import quote

from agent_bom.api.models import ScanJob
from agent_bom.api.scan_job_views import _job_response_payload

ANALYSIS_LISTS = ("cfg_edges", "call_graph", "dependency_symbol_reach")
ANALYSIS_SECTIONS = frozenset(f"ai_inventory.ast_analysis.{key}" for key in ANALYSIS_LISTS)


def dashboard_job(job: ScanJob) -> ScanJob:
    """Copy only changed containers before redaction; never mutate stored evidence."""
    result = dict(job.result) if isinstance(job.result, dict) else None
    sections: list[dict[str, Any]] = []
    if result is not None:
        result.pop("analysis_sections", None)
        inventory = result.get("ai_inventory")
        analysis = inventory.get("ast_analysis") if isinstance(inventory, dict) else None
        if isinstance(inventory, dict) and isinstance(analysis, dict):
            analysis = dict(analysis)
            for key in ANALYSIS_LISTS:
                if isinstance(analysis.get(key), list):
                    rows = analysis.pop(key)
                    name = f"ai_inventory.ast_analysis.{key}"
                    sections.append(
                        {
                            "name": name,
                            "kind": "list",
                            "count": len(rows),
                            "href": f"/v1/scan/{quote(job.job_id, safe='')}/result/{name}?offset=0&limit=100",
                        }
                    )
            result["ai_inventory"] = {**inventory, "ast_analysis": analysis}
    # Non-JSON renderings can duplicate the whole report; downloads use the full endpoint.
    projected = job.model_copy(update={"result": result, "result_document": None})
    response = _job_response_payload(projected)
    if isinstance(response.result, dict):
        # These allowlisted local links contain no report-provided path data.
        response.result["analysis_sections"] = sections
    return response
