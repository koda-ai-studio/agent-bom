"use client";

import { Collapsible } from "@/components/collapsible";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { DeploymentSurfaceRequiredState } from "@/components/deployment-surface-required-state";
import { StatStrip } from "@/components/stat-strip";
import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { Agent, agentClassCounts, api } from "@/lib/api";
import { isDeploymentSurfaceAvailable } from "@/lib/deployment-context";
import { agentRecordDisplayName, entityIdHint } from "@/lib/display-name";
import { FIRST_SCAN_ACTIONS } from "@/lib/empty-state-actions";
import { AlertCircle, GitBranch, Network, Search, Shield, X } from "lucide-react";
import { ASSET_KINDS } from "@/lib/asset-icon-registry";
import { CONFIGURED_COUNT_SCOPE, scopedHint } from "@/lib/count-scope";
import Link from "next/link";
import { useEffect, useState } from "react";
import { AgentDetailDrawer } from "./agent-detail-drawer";
import { agentCredentialCount, agentPackageCount, ConfiguredPill, useAgentStats } from "./agent-display";

export function AgentsList() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [scope, setScope] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [hintDismissed, setHintDismissed] = useState(false);
  const { counts } = useDeploymentContext();
  const estateAgents = counts?.agents?.total ?? null;

  useEffect(() => {
    api.listAgents()
      .then((r) => {
        setAgents(r.agents);
        setScope(r.scope);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const { configured, notConfigured: installedOnly, totalServers, totalPackages, totalCredentials, ecosystems, serversWithCredentials, blockedServers, remoteServers } =
    useAgentStats(agents);
  // Split real agents into AI clients (host apps) vs background/framework agents,
  // so the headline doesn't imply e.g. Cursor is an autonomous agent.
  const agentClasses = agentClassCounts(agents);
  const scannedEstate = scope === "scanned_estate";

  const filteredConfigured = configured.filter((a) =>
    !search || a.name.toLowerCase().includes(search.toLowerCase())
  );

  const activeAgent = selectedAgent
    ? configured.find((a) => a.name === selectedAgent) ?? null
    : null;

  const ecosystemHint =
    Object.entries(ecosystems)
      .map(([eco, count]) => `${eco}: ${count}`)
      .join(", ") || undefined;

  const configuredColumns: DataTableColumn<Agent>[] = [
    {
      key: "name",
      header: "Name",
      cell: (agent) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-[color:var(--foreground)]">{agentRecordDisplayName(agent)}</div>
          <div className="truncate text-xs text-[color:var(--text-tertiary)]">
            {[entityIdHint(agent.name, agentRecordDisplayName(agent)), agent.source].filter(Boolean).join(" · ")}
          </div>
        </div>
      ),
    },
    {
      key: "type",
      header: "Type",
      cell: (agent) => (
        <span className="font-mono text-xs text-[color:var(--text-secondary)]">{agent.agent_type}</span>
      ),
    },
    {
      key: "servers",
      header: "Servers",
      align: "right",
      cell: (agent) => <span className="tabular-nums">{agent.mcp_servers.length}</span>,
    },
    {
      key: "packages",
      header: "Packages",
      align: "right",
      cell: (agent) => <span className="tabular-nums">{agentPackageCount(agent)}</span>,
    },
    {
      key: "credentials",
      header: "Credentials",
      align: "right",
      cell: (agent) => {
        const count = agentCredentialCount(agent);
        return (
          <span
            className="tabular-nums"
            style={count > 0 ? { color: "var(--status-warn)" } : undefined}
          >
            {count}
          </span>
        );
      },
    },
    {
      key: "status",
      header: "Status",
      cell: () => <ConfiguredPill />,
    },
  ];

  const installedColumns: DataTableColumn<Agent>[] = [
    {
      key: "name",
      header: "Name",
      cell: (agent) => (
        <span className="font-medium text-[color:var(--text-secondary)]">{agentRecordDisplayName(agent)}</span>
      ),
    },
    {
      key: "type",
      header: "Type",
      cell: (agent) => (
        <span className="font-mono text-xs text-[color:var(--text-tertiary)]">{agent.agent_type}</span>
      ),
    },
    {
      key: "config",
      header: "Config path",
      cell: (agent) => (
        <span className="truncate font-mono text-xs text-[color:var(--text-tertiary)]">
          {agent.config_path || "—"}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: () => (
        <span
          className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em]"
          style={{ color: "var(--status-warn)" }}
        >
          <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "var(--status-warn)" }} aria-hidden="true" />
          not configured
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">Agents</h1>
          <p className="mt-1 text-sm text-[color:var(--text-secondary)]">
            Discovered AI clients/hosts and background agents, with their MCP servers
            {scannedEstate ? (
              <> from this workspace&apos;s scans, one per project or AI client.</>
            ) : estateAgents !== null ? (
              <> on this API host. Estate agents: {estateAgents} <Link href="/inventory?type=agent" className="text-[color:var(--accent)]">Open agent inventory</Link></>
            ) : null}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link
            href="/agents/topology"
            className="agents-secondary-action"
          >
            <Network className="h-4 w-4" />
            Agent mesh
          </Link>
          <Link
            href="/mesh"
            className="agents-secondary-action"
          >
            <GitBranch className="h-4 w-4" />
            Mesh View
          </Link>
        </div>
      </div>

      {!loading && agents.length > 0 && !hintDismissed && (
          <div className="agents-info-callout">
          <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[color:var(--accent)]" />
          <p className="min-w-0 flex-1">
            <span className="font-semibold text-[color:var(--foreground)]">Inventory-first:</span> this page is useful on
            discovery alone — MCP servers, transport, tools, and env-backed credentials. Proxy and gateway add runtime
            enforcement later; they are not required for visibility.
          </p>
          <button
            type="button"
            onClick={() => setHintDismissed(true)}
            aria-label="Dismiss hint"
            className="agents-icon-button"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {!loading && agents.length > 0 && (
        <StatStrip
          data-testid="agents-kpis"
          items={[
            {
              label: scannedEstate ? "Scanned agents" : "Agents on this host",
              value: agents.length,
              icon: ASSET_KINDS.agent.icon,
              hint: !scannedEstate && estateAgents !== null
                ? `${estateAgents.toLocaleString()} in the estate`
                : `${configured.length} configured${installedOnly.length > 0 ? ` · ${installedOnly.length} not` : ""}`,
              title: CONFIGURED_COUNT_SCOPE.title,
            },
            {
              label: "MCP servers",
              value: totalServers,
              icon: ASSET_KINDS.mcp_server.icon,
              hint: scopedHint(CONFIGURED_COUNT_SCOPE.caption, `${remoteServers} remote`),
              title: CONFIGURED_COUNT_SCOPE.title,
            },
            {
              label: "Packages",
              value: totalPackages,
              icon: ASSET_KINDS.package.icon,
              hint: scopedHint(CONFIGURED_COUNT_SCOPE.caption, ecosystemHint),
              title: CONFIGURED_COUNT_SCOPE.title,
            },
            {
              label: "Unique credentials",
              value: totalCredentials,
              icon: ASSET_KINDS.credential.icon,
              accent: "warn",
              hint: `across ${serversWithCredentials} servers`,
            },
            {
              label: "Blocked / risky",
              value: blockedServers,
              icon: AlertCircle,
              accent: "critical",
            },
            {
              label: "Clients · background",
              value: `${agentClasses.client} · ${agentClasses.background}`,
              icon: Network,
            },
          ]}
        />
      )}

      {!loading && agents.length > 0 && (
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full sm:max-w-sm">
            <Search className="agents-search-icon" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search agents or agent type"
              className="agents-search"
            />
          </div>
          <p className="text-xs text-[color:var(--text-tertiary)]">
            {filteredConfigured.length} configured · {installedOnly.length} installed only
          </p>
        </div>
      )}

      {loading && (
        <PageLoadingState
          title="Discovering agents"
          detail="Loading configured agents, MCP servers, packages, credentials, and inventory metadata from the API."
          data-testid="agents-loading-state"
        />
      )}
      {error && (
        <PageErrorState
          title="Could not load agents"
          detail={error}
          suggestions={[
            "Confirm the API is reachable for this dashboard session.",
            "Run a local discovery scan if this is a first-run environment.",
            "Use the scan page to generate a fresh inventory artifact.",
          ]}
          command="agent-bom agents --demo --offline"
        />
      )}

      {!loading && !error && agents.length === 0 &&
        (counts && !isDeploymentSurfaceAvailable("agents", counts) ? (
          <DeploymentSurfaceRequiredState surface="agents" counts={counts} />
        ) : (
          <PageEmptyState
            title="No agents discovered yet"
            detail="Run discovery against this workspace or load a demo scan to populate configured agents, MCP servers, packages, and credentials."
            icon={ASSET_KINDS.mcp_server.icon}
            suggestions={[
              "Start with the offline demo if you need a reproducible sample.",
              "Run a local scan from the same environment where MCP clients are configured.",
              "Open the mesh view after discovery to inspect agent and server relationships.",
            ]}
            command="agent-bom agents --demo --offline"
            actions={FIRST_SCAN_ACTIONS}
            data-testid="agents-empty-state"
          />
        ))}

      {/* Configured agents — dense table, row → detail drawer */}
      {!loading && configured.length > 0 && (
        <section className="space-y-2">
          <div className="flex items-baseline justify-between">
            <h2 className="text-base font-semibold text-[color:var(--foreground)]">Configured agents</h2>
            <p className="text-xs text-[color:var(--text-tertiary)]">Row → servers, tools, and credentials</p>
          </div>
          <DataTable<Agent>
            data-testid="agents-configured-table"
            columns={configuredColumns}
            rows={filteredConfigured}
            rowKey={(agent) => agent.name}
            onRowClick={(agent) => setSelectedAgent(agent.name)}
            selectedKey={selectedAgent ?? undefined}
            maxHeight="34rem"
            caption="Configured agents with server, package, and credential counts"
            empty={
              search
                ? "No configured agents match the current search."
                : "No configured agents in this inventory."
            }
          />
        </section>
      )}

      {/* Installed but not configured */}
      {!loading && installedOnly.length > 0 && (
        <Collapsible
          title="Installed but not configured"
          icon={AlertCircle}
          count={installedOnly.length}
          defaultOpen={false}
        >
          <p className="mb-3 text-xs text-[color:var(--text-secondary)]">
            Binaries detected on PATH. Run setup to configure MCP servers.
          </p>
          <DataTable<Agent>
            data-testid="agents-installed-table"
            columns={installedColumns}
            rows={installedOnly}
            rowKey={(agent, index) => `${agent.name}-${index}`}
            maxHeight="24rem"
            caption="Installed but unconfigured agents"
          />
        </Collapsible>
      )}

      <AgentDetailDrawer agent={activeAgent} open={activeAgent != null} onClose={() => setSelectedAgent(null)} />
    </div>
  );
}
