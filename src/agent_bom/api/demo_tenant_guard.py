"""Keep real evidence out of the labeled demo tenant.

A server started with ``--demo-estate`` serves a synthetic estate under the
showcase tenant, and every surface labels that tenant "Demo data". Evidence
pushed, synced or collected into it would render under the same label, so
ingest operations fail closed for that tenant whatever the caller's role. The
check runs in the tenant-binding step every authenticated principal passes
through. Other tenants on the same server are not affected.
"""

from __future__ import annotations

import re
from functools import lru_cache

from starlette.responses import JSONResponse

from agent_bom.demo_estate import demo_estate_enabled

# Operations that admit scan results, inventory, runtime or compliance
# evidence into the caller's tenant.
DEMO_TENANT_INGEST_OPERATIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/v1/results/push"),
        ("POST", "/v1/fleet/sync"),
        ("POST", "/v1/scan"),
        ("POST", "/v1/skills/scan"),
        ("POST", "/v1/sources/{source_id}/run"),
        ("POST", "/v1/sources/run-cohort"),
        ("POST", "/v1/cloud/connections/{connection_id}/scan"),
        ("POST", "/v1/cloud/connections/events/ingest"),
        ("POST", "/v1/cloud/runtime-evidence/ingest"),
        ("POST", "/v1/compliance/ingest"),
        ("POST", "/v1/findings/triage/vex/ingest"),
        ("POST", "/v1/endpoint-connectors/{connection_id}/sync"),
        ("POST", "/v1/ocsf/ingest"),
        ("POST", "/v1/proxy/audit"),
        ("POST", "/v1/runtime/events"),
        ("POST", "/v1/traces"),
        ("POST", "/v1/traces/connectors/langfuse/collect"),
        ("POST", "/v1/traces/connectors/{provider}/pull"),
    }
)

# Write routes whose path reads like ingest but that store no external
# evidence: stateless analysis, verification, or operator actions on records
# that already exist. Declared so a new ingest route cannot go unclassified.
NON_INGEST_WRITE_OPERATIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/scim/v2/Bulk"),  # identity provisioning, not evidence
        ("POST", "/v1/agent-lifecycle/runs"),
        ("POST", "/v1/audit/export/verify"),
        ("POST", "/v1/campaigns/{campaign_id}/tickets/sync"),
        ("POST", "/v1/exports/destinations/{destination_id}/run"),
        ("POST", "/v1/findings/bulk"),  # triage of existing findings
        ("POST", "/v1/observability/adoption/events"),  # product usage counters
        ("POST", "/v1/runtime/approval-queue/{item_id}/decision"),
        ("POST", "/v1/runtime/drift/incidents/{incident_id}/resolve"),
        ("POST", "/v1/runtime/profiles/evaluate"),
        ("POST", "/v1/scan/browser-extensions"),
        ("POST", "/v1/scan/check"),
        ("POST", "/v1/scan/dataset-cards"),
        ("POST", "/v1/scan/model-files"),
        ("POST", "/v1/scan/model-provenance"),
        ("POST", "/v1/scan/prompt-scan"),
        ("POST", "/v1/scan/training-pipelines"),
        ("POST", "/v1/scan/{job_id}/cancel"),
        ("POST", "/v1/ticketing/tickets/{ticket_id}/sync"),
        ("POST", "/v1/traces/attack-paths"),
    }
)

DEMO_TENANT_INGEST_DETAIL = (
    "This server runs the labeled demo estate; its demo tenant does not accept real evidence. "
    "Send results to a server started without --demo-estate, or to a separate tenant."
)


@lru_cache(maxsize=1)
def _compiled() -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple(
        (method, re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(template)) + "$"))
        for method, template in sorted(DEMO_TENANT_INGEST_OPERATIONS)
    )


def is_demo_tenant_ingest(method: str, path: str) -> bool:
    normalized = method.upper()
    return any(normalized == op_method and pattern.match(path) for op_method, pattern in _compiled())


def demo_tenant_ingest_rejection(method: str, path: str, tenant_id: str) -> JSONResponse | None:
    """The 409 to return for an ingest into the demo tenant, or ``None`` to proceed."""
    if not demo_estate_enabled():
        return None
    from agent_bom.demo_estate.showcase_constants import SHOWCASE_TENANT

    if tenant_id != SHOWCASE_TENANT or not is_demo_tenant_ingest(method, path):
        return None
    return JSONResponse(status_code=409, content={"detail": DEMO_TENANT_INGEST_DETAIL})
