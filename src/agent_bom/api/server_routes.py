"""Domain route registration in its public precedence order."""

from __future__ import annotations

from fastapi import FastAPI

from agent_bom.api.routes.adoption import router as _adoption_router
from agent_bom.api.routes.advisory_affected import router as _advisory_affected_router
from agent_bom.api.routes.agent_lifecycle import router as _agent_lifecycle_router
from agent_bom.api.routes.agent_manifest import router as _agent_manifest_router
from agent_bom.api.routes.ai_scans import router as _ai_scans_router
from agent_bom.api.routes.assets import router as _assets_router
from agent_bom.api.routes.blueprints import router as _blueprints_router
from agent_bom.api.routes.brief import router as _brief_router
from agent_bom.api.routes.campaigns import router as _campaigns_router
from agent_bom.api.routes.cloud import router as _cloud_router
from agent_bom.api.routes.cloud_connections import router as _cloud_connections_router
from agent_bom.api.routes.compliance import router as _compliance_router
from agent_bom.api.routes.connectors import router as _connectors_router
from agent_bom.api.routes.credentials import router as _credentials_router
from agent_bom.api.routes.datasets import router as _datasets_router
from agent_bom.api.routes.demo_estate import router as _demo_estate_router
from agent_bom.api.routes.discovery import router as _discovery_router
from agent_bom.api.routes.enterprise import router as _enterprise_router
from agent_bom.api.routes.entitlements import router as _entitlements_router
from agent_bom.api.routes.estate import router as _estate_router
from agent_bom.api.routes.evaluations import router as _evaluations_router
from agent_bom.api.routes.exports import router as _exports_router
from agent_bom.api.routes.fleet import router as _fleet_router
from agent_bom.api.routes.frameworks import router as _frameworks_router
from agent_bom.api.routes.gateway import router as _gateway_router
from agent_bom.api.routes.gateway_feed import router as _gateway_feed_router
from agent_bom.api.routes.governance import router as _governance_router
from agent_bom.api.routes.graph import router as _graph_router
from agent_bom.api.routes.graph_correlations import router as _graph_correlations_router
from agent_bom.api.routes.graph_scenarios import router as _graph_scenarios_router
from agent_bom.api.routes.identities import router as _identities_router
from agent_bom.api.routes.intel import router as _intel_router
from agent_bom.api.routes.inventory_assets import router as _inventory_assets_router
from agent_bom.api.routes.kspm import router as _kspm_router
from agent_bom.api.routes.mcp_config import router as _mcp_config_router
from agent_bom.api.routes.mitre import router as _mitre_router
from agent_bom.api.routes.model_keys import router as _model_keys_router
from agent_bom.api.routes.observability import infra_router as _observability_infra_router
from agent_bom.api.routes.observability import router as _observability_router
from agent_bom.api.routes.operator_advisories import router as _operator_advisories_router
from agent_bom.api.routes.overview import router as _overview_router
from agent_bom.api.routes.plugins import router as _plugins_router
from agent_bom.api.routes.posture_streaming import router as _posture_streaming_router
from agent_bom.api.routes.privacy import router as _privacy_router
from agent_bom.api.routes.proxy import router as _proxy_router
from agent_bom.api.routes.proxy import ws_router as _proxy_ws_router
from agent_bom.api.routes.reports import router as _reports_router
from agent_bom.api.routes.runtime_blueprints import router as _runtime_blueprints_router
from agent_bom.api.routes.scan import router as _scan_router
from agent_bom.api.routes.schedules import router as _schedules_router
from agent_bom.api.routes.scim import router as _scim_router
from agent_bom.api.routes.self_posture import router as _self_posture_router
from agent_bom.api.routes.skills import router as _skills_router
from agent_bom.api.routes.sources import router as _sources_router
from agent_bom.api.routes.ticketing import router as _ticketing_router
from agent_bom.api.routes.webhooks import router as _webhooks_router
from agent_bom.api.versioning import create_v1_api_router


def register_domain_routes(application: FastAPI) -> None:
    _v1_api_router = create_v1_api_router()

    for _router in (
        _adoption_router,
        _brief_router,
        _assets_router,
        _agent_manifest_router,
        _agent_lifecycle_router,
        _campaigns_router,
        _cloud_router,
        _cloud_connections_router,
        _compliance_router,
        _connectors_router,
        _credentials_router,
        _datasets_router,
        _demo_estate_router,
        _discovery_router,
        _entitlements_router,
        _estate_router,
        _enterprise_router,
        _exports_router,
        _fleet_router,
        _evaluations_router,
        _frameworks_router,
        _gateway_router,
        _gateway_feed_router,
        _governance_router,
        _blueprints_router,
        _graph_router,
        _graph_correlations_router,
        _graph_scenarios_router,
        _identities_router,
        _intel_router,
        _operator_advisories_router,
        _advisory_affected_router,
        _inventory_assets_router,
        _kspm_router,
        _mcp_config_router,
        _mitre_router,
        _model_keys_router,
        _observability_router,
        _overview_router,
        _plugins_router,
        _posture_streaming_router,
        _privacy_router,
        _proxy_router,
        _reports_router,
        _runtime_blueprints_router,
        _scan_router,
        _ai_scans_router,
        _schedules_router,
        _self_posture_router,
        _skills_router,
        _sources_router,
        _ticketing_router,
        _webhooks_router,
    ):
        _v1_api_router.include_router(_router)

    application.include_router(_v1_api_router)
    # SCIM base path is RFC-driven (/scim/v2 by default), not under API_V1_PREFIX.
    application.include_router(_scim_router)
    # Prometheus scrape surface stays unversioned (infra contract).
    application.include_router(_observability_infra_router)
    # Proxy live streams are root-level WebSocket paths (/ws/proxy/*), not /v1.
    application.include_router(_proxy_ws_router)
