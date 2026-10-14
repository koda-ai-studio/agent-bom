"""Snowflake AI-surface agent assembly and governance-report mining for the discovery facade."""

from __future__ import annotations

from typing import Any

from agent_bom.governance import GovernanceReport
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from ..normalization import build_cloud_origin
from ..snowflake_ai_surfaces import _discover_cortex_agents as _discover_cortex_agents
from ..snowflake_ai_surfaces import _discover_cortex_services as _discover_cortex_services
from ..snowflake_ai_surfaces import _discover_custom_tools as _discover_custom_tools
from ..snowflake_ai_surfaces import _discover_from_query_history as _discover_from_query_history
from ..snowflake_ai_surfaces import _discover_mcp_servers as _discover_mcp_servers
from ..snowflake_ai_surfaces import _discover_snowpark_packages as _discover_snowpark_packages
from ..snowflake_ai_surfaces import _discover_streamlit_apps as _discover_streamlit_apps
from ..snowflake_governance_findings import _derive_findings as _derive_findings
from ..snowflake_governance_mining import _mine_access_history as _mine_access_history
from ..snowflake_governance_mining import _mine_cortex_agent_usage as _mine_cortex_agent_usage
from ..snowflake_governance_mining import _mine_grants_to_roles as _mine_grants_to_roles
from ..snowflake_governance_mining import _mine_tag_references as _mine_tag_references
from ..snowflake_notebooks import _discover_snowflake_notebooks as _discover_snowflake_notebooks
from .cortex_agents import collect_cortex_agents
from .cortex_telemetry import fetch_cortex_agent_spans


def _snowflake_cloud_origin(
    *,
    account: str,
    service: str,
    resource_type: str,
    resource_id: str,
    resource_name: str,
    database: str = "",
    schema: str = "",
) -> dict[str, Any]:
    raw_identity = {
        "account": account,
        "database": database,
        "schema": schema,
        "name": resource_name,
    }
    return build_cloud_origin(
        provider="snowflake",
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        account_id=account,
        raw_identity=raw_identity,
    )


def _discover_ai_surfaces(
    conn: Any,
    account: str,
    database: str | None,
    schema: str | None,
    agents: list[Agent],
    warnings: list[str],
) -> None:
    """Run each AI-surface discoverer in order, folding agents and warnings into the caller's lists."""
    # ── Cortex Search Services ────────────────────────────────────────
    cortex_agents, cortex_warns = _discover_cortex_services(conn, account, database, schema)
    agents.extend(cortex_agents)
    warnings.extend(cortex_warns)

    # ── Cortex Agents (v2025 Agent framework) ─────────────────────────
    cortex_agent_list, ca_warns = _discover_cortex_agents(conn, account)
    agents.extend(cortex_agent_list)
    warnings.extend(ca_warns)

    # ── Snowflake MCP Servers (GA Nov 2025) ───────────────────────────
    mcp_agents, mcp_warns = _discover_mcp_servers(conn, account)
    agents.extend(mcp_agents)
    warnings.extend(mcp_warns)

    # ── Query History audit (supplementary) ───────────────────────────
    qh_agents, qh_warns = _discover_from_query_history(conn, account)
    agents.extend(qh_agents)
    warnings.extend(qh_warns)

    # ── Custom Tools (functions & procedures) ─────────────────────────
    custom_tools, ct_warns = _discover_custom_tools(conn, account)
    warnings.extend(ct_warns)
    _attach_custom_tools(agents, custom_tools, account)

    # ── Snowpark packages ─────────────────────────────────────────────
    snowpark_pkgs, sp_warns = _discover_snowpark_packages(conn, account)
    warnings.extend(sp_warns)

    # If we found Snowpark packages but no Cortex agents, create a generic agent
    all_cortex = cortex_agents + cortex_agent_list
    if snowpark_pkgs and not all_cortex:
        agents.append(_snowpark_agent(snowpark_pkgs, account))

    # ── Streamlit apps ────────────────────────────────────────────────
    streamlit_agents, st_warns = _discover_streamlit_apps(conn, account)
    agents.extend(streamlit_agents)
    warnings.extend(st_warns)

    # ── Snowflake Notebooks ─────────────────────────────────────────
    notebook_agents, nb_warns = _discover_snowflake_notebooks(conn, account)
    agents.extend(notebook_agents)
    warnings.extend(nb_warns)


def _attach_custom_tools(agents: list[Agent], custom_tools: list[MCPTool], account: str) -> None:
    """Inventory account UDFs/procedures as one standalone tool collection.

    They are never attached to Cortex Agents: an agent reaches only the
    functions and procedures its own specification declares.
    """
    if custom_tools:
        tool_server = MCPServer(
            name="snowflake-custom-tools",
            transport=TransportType.UNKNOWN,
            tools=custom_tools,
        )
        agents.append(
            Agent(
                name=f"snowflake-tools:{account}",
                agent_type=AgentType.CUSTOM,
                config_path=f"snowflake://{account}/custom-tools",
                source="snowflake-tools",
                mcp_servers=[tool_server],
                metadata={
                    "cloud_origin": _snowflake_cloud_origin(
                        account=account,
                        service="custom-tools",
                        resource_type="tool-collection",
                        resource_id=f"{account}/custom-tools",
                        resource_name="custom-tools",
                    )
                },
            )
        )


def _snowpark_agent(snowpark_pkgs: list[Package], account: str) -> Agent:
    """Generic agent carrying Snowpark packages when no Cortex agent was found."""
    server = MCPServer(
        name="snowpark-packages",
        transport=TransportType.UNKNOWN,
        packages=snowpark_pkgs,
    )
    return Agent(
        name=f"snowflake:{account}",
        agent_type=AgentType.CUSTOM,
        config_path=f"snowflake://{account}",
        source="snowflake",
        mcp_servers=[server],
        metadata={
            "cloud_origin": _snowflake_cloud_origin(
                account=account,
                service="snowpark",
                resource_type="package-environment",
                resource_id=account,
                resource_name=account,
            )
        },
    )


def _mine_governance_report(conn: Any, days: int, report: GovernanceReport) -> None:
    """Mine the governance ACCOUNT_USAGE views into *report*, then derive its findings."""
    # 1. ACCESS_HISTORY — who accessed what tables/columns
    access_records, access_warns = _mine_access_history(conn, days)
    report.access_records = access_records
    report.warnings.extend(access_warns)

    # 2. GRANTS_TO_ROLES — privilege grants
    grants, grant_warns = _mine_grants_to_roles(conn)
    report.privilege_grants = grants
    report.warnings.extend(grant_warns)

    # 3. TAG_REFERENCES — data classification tags
    tags, tag_warns = _mine_tag_references(conn)
    report.data_classifications = tags
    report.warnings.extend(tag_warns)

    # 4. CORTEX_AGENT_USAGE_HISTORY — agent telemetry
    usage, usage_warns = _mine_cortex_agent_usage(conn, days)
    report.agent_usage = usage
    report.warnings.extend(usage_warns)

    # 5. Cortex Agents — DESCRIBE AGENT specs, agent grants, observability spans
    report.cortex_agents = collect_cortex_agents(conn, report.account, report.warnings)
    for agent in report.cortex_agents:
        report.cortex_events.extend(fetch_cortex_agent_spans(conn, agent, days, report.warnings))

    # 6. Derive governance findings from raw data
    report.findings = _derive_findings(report)
