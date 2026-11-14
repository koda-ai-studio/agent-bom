"use client";

import { AlertCircle, Network } from "lucide-react";

import { StatStrip } from "@/components/stat-strip";
import { type Agent, agentClassCounts, type AgentsResponse } from "@/lib/api";
import { ASSET_KINDS } from "@/lib/asset-icon-registry";
import { AGENT_COUNT_SCOPE, CONFIGURED_COUNT_SCOPE, PACKAGE_COUNT_SCOPE, scopedHint } from "@/lib/count-scope";

import { useAgentStats } from "./agent-display";

export type AgentsSummary = AgentsResponse["summary"];

/** Only live discovery of this API host is "on this host"; scanned or unlabelled populations never claim to be. */
export function agentsCountLabel(scope: string | undefined): string {
  if (scope === "local_discovery") return AGENT_COUNT_SCOPE.host.label;
  if (scope === "scanned_estate") return AGENT_COUNT_SCOPE.scanned.label;
  return "Agents";
}

function agentsCountTitle(scope: string | undefined): string {
  const own = scope === "local_discovery" ? AGENT_COUNT_SCOPE.host.title : scope === "scanned_estate" ? AGENT_COUNT_SCOPE.scanned.title : "";
  return [own, AGENT_COUNT_SCOPE.snapshot.title, CONFIGURED_COUNT_SCOPE.title].filter(Boolean).join(" ");
}

/** Population totals for an older full-list response that carries no server summary. */
export function useFallbackSummary(agents: Agent[]): AgentsSummary {
  const stats = useAgentStats(agents);
  return {
    agents: agents.length,
    configured: stats.configured.length,
    not_configured: stats.notConfigured.length,
    mcp_servers: stats.totalServers,
    remote_servers: stats.remoteServers,
    packages: stats.totalPackages,
    ecosystems: stats.ecosystems,
    unique_credentials: stats.totalCredentials,
    servers_with_credentials: stats.serversWithCredentials,
    blocked_servers: stats.blockedServers,
  };
}

export function AgentsKpiStrip({
  summary,
  classCounts,
  scope,
  estateAgents,
}: {
  summary: AgentsSummary;
  classCounts: ReturnType<typeof agentClassCounts>;
  scope: string | undefined;
  estateAgents: number | null;
}) {
  const ecosystemHint =
    Object.entries(summary.ecosystems)
      .map(([eco, count]) => `${eco}: ${count}`)
      .join(", ") || undefined;
  return (
    <StatStrip
      data-testid="agents-kpis"
      items={[
        {
          label: agentsCountLabel(scope),
          value: summary.agents,
          icon: ASSET_KINDS.agent.icon,
          // The Overview / posture number, named, so the two never read as a contradiction.
          hint: estateAgents !== null
            ? `${estateAgents.toLocaleString()} ${AGENT_COUNT_SCOPE.snapshot.caption}`
            : `${summary.configured.toLocaleString()} configured${summary.not_configured > 0 ? ` · ${summary.not_configured.toLocaleString()} not` : ""}`,
          title: agentsCountTitle(scope),
        },
        {
          label: "MCP servers",
          value: summary.mcp_servers,
          icon: ASSET_KINDS.mcp_server.icon,
          hint: scopedHint(CONFIGURED_COUNT_SCOPE.caption, `${summary.remote_servers.toLocaleString()} remote`),
          title: CONFIGURED_COUNT_SCOPE.title,
        },
        {
          label: PACKAGE_COUNT_SCOPE.references.label,
          value: summary.packages,
          icon: ASSET_KINDS.package.icon,
          hint: scopedHint(PACKAGE_COUNT_SCOPE.references.caption, ecosystemHint),
          title: PACKAGE_COUNT_SCOPE.references.title,
        },
        {
          label: "Unique credentials",
          value: summary.unique_credentials,
          icon: ASSET_KINDS.credential.icon,
          accent: "warn",
          hint: `across ${summary.servers_with_credentials.toLocaleString()} servers`,
        },
        {
          label: "Launch-blocked servers",
          value: summary.blocked_servers,
          icon: AlertCircle,
          ...(summary.blocked_servers > 0 ? { accent: "critical" as const } : {}),
          hint: "blocked by launch policy; vulnerabilities are on Findings",
        },
        {
          label: "Clients · background",
          value: `${classCounts.client.toLocaleString()} · ${classCounts.background.toLocaleString()}`,
          icon: Network,
        },
      ]}
    />
  );
}
