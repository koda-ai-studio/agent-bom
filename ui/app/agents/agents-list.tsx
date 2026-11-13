"use client";

import { DataTable, type DataTableColumn } from "@/components/data-table";
import { DeploymentSurfaceRequiredState } from "@/components/deployment-surface-required-state";
import { PaginationBar } from "@/components/pagination-bar";
import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { Agent, agentClassCounts, isConfigured } from "@/lib/api";
import type { AgentSortKey } from "@/lib/api-inventory";
import { isDeploymentSurfaceAvailable } from "@/lib/deployment-context";
import { agentRecordDisplayName, entityIdHint } from "@/lib/display-name";
import { FIRST_SCAN_ACTIONS } from "@/lib/empty-state-actions";
import { GitBranch, Network, Search, Shield, Workflow, X } from "lucide-react";
import { ASSET_KINDS } from "@/lib/asset-icon-registry";
import { AGENT_COUNT_SCOPE } from "@/lib/count-scope";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { AgentDetailDrawer } from "./agent-detail-drawer";
import { agentCredentialCount, agentPackageCount, ConfiguredPill } from "./agent-display";
import { AgentsFilterChips } from "./agents-filter-chips";
import { AgentsKpiStrip, useFallbackSummary } from "./agents-kpi-strip";
import {
  AGENT_PAGE_SIZES,
  agentListApiParams,
  agentListSearch,
  type AgentListState,
  nextAgentSort,
  readAgentListState,
  toggleFacet,
} from "./agents-list-state";
import { useAgentsPage } from "./use-agents-page";

export { agentsCountLabel } from "./agents-kpi-strip";

const SEARCH_DEBOUNCE_MS = 300;
const SORTABLE = new Set<string>(["name", "servers", "packages", "credentials", "findings"]);

function agentRowKey(agent: Agent, index: number): string {
  return agent.canonical_id || `${agent.name}-${index}`;
}

function agentFindingCount(agent: Agent): number {
  return agent.mcp_servers.reduce(
    (sum, server) => sum + server.packages.reduce((inner, pkg) => inner + ((pkg as { vulnerabilities?: unknown[] }).vulnerabilities?.length ?? 0), 0),
    0,
  );
}

function NotConfiguredPill() {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em]" style={{ color: "var(--status-warn)" }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "var(--status-warn)" }} aria-hidden="true" />
      not configured
    </span>
  );
}

function agentColumns(scannedFindings: boolean): DataTableColumn<Agent>[] {
  return [
    {
      key: "name",
      header: "Name",
      sortable: true,
      cell: (agent) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-[color:var(--foreground)]">{agentRecordDisplayName(agent)}</div>
          <div className="truncate text-xs text-[color:var(--text-tertiary)]">
            {[entityIdHint(agent.name, agentRecordDisplayName(agent)), agent.source].filter(Boolean).join(" · ")}
          </div>
        </div>
      ),
    },
    { key: "type", header: "Type", cell: (agent) => <span className="font-mono text-xs text-[color:var(--text-secondary)]">{agent.agent_type}</span> },
    { key: "servers", header: "Servers", align: "right", sortable: true, cell: (agent) => <span className="tabular-nums">{agent.mcp_servers.length}</span> },
    { key: "packages", header: "Packages", align: "right", sortable: true, cell: (agent) => <span className="tabular-nums">{agentPackageCount(agent)}</span> },
    {
      key: "credentials",
      header: "Credentials",
      align: "right",
      sortable: true,
      cell: (agent) => {
        const count = agentCredentialCount(agent);
        return <span className="tabular-nums" style={count > 0 ? { color: "var(--status-warn)" } : undefined}>{count}</span>;
      },
    },
    {
      key: "findings",
      header: <span title="Package vulnerability instances recorded on this agent's scanned packages">Vulns</span>,
      align: "right",
      // Live host discovery runs no CVE scan, so a zero there would claim a clean agent.
      sortable: scannedFindings,
      cell: (agent) => (scannedFindings ? <span className="tabular-nums">{agentFindingCount(agent)}</span> : <span title="Not scanned on this host">—</span>),
    },
    { key: "status", header: "Status", cell: (agent) => (isConfigured(agent) ? <ConfiguredPill /> : <NotConfiguredPill />) },
  ];
}

export function AgentsList() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [state, setState] = useState<AgentListState>(() => readAgentListState(new URLSearchParams(searchParams.toString())));
  const [searchText, setSearchText] = useState(state.q);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [hintDismissed, setHintDismissed] = useState(false);
  const { counts } = useDeploymentContext();
  const estateAgents = counts?.agents?.total ?? null;

  const apiParams = useMemo(() => agentListApiParams(state), [state]);
  const { data, loading, error } = useAgentsPage(apiParams);
  const agents = useMemo(() => data?.agents ?? [], [data]);
  const fallbackSummary = useFallbackSummary(agents);
  const summary = data?.summary ?? fallbackSummary;
  const classCounts = data?.count_by_class
    ? { client: data.count_by_class.client ?? 0, background: data.count_by_class.background ?? 0 }
    : agentClassCounts(agents);
  const scope = data?.scope;
  const scannedEstate = scope === "scanned_estate";
  const population = data?.count ?? summary.agents;
  const total = data?.total ?? agents.length;
  const totalPages = Math.max(1, Math.ceil(total / state.pageSize));
  const firstLoad = loading && data === null;

  useEffect(() => {
    const timer = setTimeout(() => {
      setState((current) => (current.q === searchText.trim() ? current : { ...current, q: searchText.trim(), page: 1 }));
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchText]);

  useEffect(() => {
    const current = searchParams.toString();
    const qs = agentListSearch(state, new URLSearchParams(current));
    if (qs !== current) router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    // URL mirrors list state; reading searchParams here would loop on every replace.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state, pathname, router]);

  // A deep link past the last page (or a filter that shrank the set) lands on the last real page.
  useEffect(() => {
    if (!loading && data && agents.length === 0 && total > 0 && state.page > totalPages) {
      setState((current) => ({ ...current, page: totalPages }));
    }
  }, [loading, data, agents.length, total, state.page, totalPages]);

  const activeAgent = selectedKey ? agents.find((agent, index) => agentRowKey(agent, index) === selectedKey) ?? null : null;
  const filtersActive = Boolean(state.q || state.type.length || state.status.length || state.source.length);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">Agents</h1>
          <p className="mt-1 text-sm text-[color:var(--text-secondary)]">
            Discovered AI clients/hosts and background agents, with their MCP servers
            {scannedEstate ? (
              <> from this workspace&apos;s scans, one per project or AI client.</>
            ) : scope === "local_discovery" && estateAgents !== null ? (
              <> on this API host. {estateAgents.toLocaleString()} {AGENT_COUNT_SCOPE.snapshot.caption} <Link href="/inventory?type=agent" className="text-[color:var(--accent)]">Open agent inventory</Link></>
            ) : null}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link href="/agents/architecture" className="agents-secondary-action"><Workflow className="h-4 w-4" />Architecture</Link>
          <Link href="/agents/topology" className="agents-secondary-action"><Network className="h-4 w-4" />Agent mesh</Link>
          <Link href="/mesh" className="agents-secondary-action"><GitBranch className="h-4 w-4" />Mesh View</Link>
        </div>
      </div>

      {data && population > 0 && !hintDismissed && (
        <div className="agents-info-callout">
          <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[color:var(--accent)]" />
          <p className="min-w-0 flex-1">
            <span className="font-semibold text-[color:var(--foreground)]">Inventory-first:</span> this page is useful on
            discovery alone — MCP servers, transport, tools, and env-backed credentials. Proxy and gateway add runtime
            enforcement later; they are not required for visibility.
          </p>
          <button type="button" onClick={() => setHintDismissed(true)} aria-label="Dismiss hint" className="agents-icon-button">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {data && population > 0 && <AgentsKpiStrip summary={summary} classCounts={classCounts} scope={scope} estateAgents={estateAgents} />}

      {data && population > 0 && (
        <div className="space-y-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="relative w-full sm:max-w-sm">
              <Search className="agents-search-icon" />
              <input
                type="search"
                aria-label="Search agents"
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                maxLength={200}
                placeholder="Search agents or agent type"
                className="agents-search"
              />
            </div>
            <p className="text-xs text-[color:var(--text-tertiary)]" aria-live="polite" data-testid="agents-match-count">
              {total.toLocaleString()} of {population.toLocaleString()} agents{filtersActive ? " match" : ""}
            </p>
          </div>
          <AgentsFilterChips
            facets={data.facets}
            selected={{ type: state.type, status: state.status, source: state.source }}
            onToggle={(facet, value) => setState((current) => toggleFacet(current, facet, value))}
          />
        </div>
      )}

      {firstLoad && (
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

      {!loading && !error && data && population === 0 &&
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

      {data && population > 0 && (
        <section className="space-y-2">
          <DataTable<Agent>
            data-testid="agents-table"
            columns={agentColumns(scope !== "local_discovery")}
            rows={agents}
            rowKey={agentRowKey}
            onRowClick={(agent) => setSelectedKey(agentRowKey(agent, agents.indexOf(agent)))}
            selectedKey={selectedKey ?? undefined}
            sort={state.sort ? { key: state.sort, direction: state.order } : undefined}
            onSortChange={(key) => {
              if (SORTABLE.has(key)) setState((current) => ({ ...current, ...nextAgentSort(current, key as AgentSortKey), page: 1 }));
            }}
            loading={loading}
            loadingRows={Math.min(state.pageSize, 10)}
            maxHeight="38rem"
            caption="Agents with server, package, credential, and vulnerability counts"
            empty={filtersActive ? "No agents match the current search and filters." : "No agents on this page."}
          />
          <div className="flex flex-wrap items-center justify-between gap-3">
            <PaginationBar
              className="flex-1"
              page={state.page}
              totalPages={totalPages}
              totalItems={total}
              itemLabel="agents"
              previousDisabled={loading || state.page <= 1}
              nextDisabled={loading || !data.has_more}
              onPrevious={() => setState((current) => ({ ...current, page: Math.max(1, current.page - 1) }))}
              onNext={() => setState((current) => ({ ...current, page: current.page + 1 }))}
            />
            <label className="flex items-center gap-2 text-xs text-[color:var(--text-tertiary)]">
              Rows per page
              <select
                aria-label="Rows per page"
                value={state.pageSize}
                onChange={(event) => setState((current) => ({ ...current, pageSize: Number(event.target.value), page: 1 }))}
                className="cursor-pointer rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-1 text-xs text-[color:var(--foreground)]"
              >
                {AGENT_PAGE_SIZES.map((size) => <option key={size} value={size}>{size}</option>)}
              </select>
            </label>
          </div>
        </section>
      )}

      <AgentDetailDrawer agent={activeAgent} open={activeAgent != null} onClose={() => setSelectedKey(null)} />
    </div>
  );
}
