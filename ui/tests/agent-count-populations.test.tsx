import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AgentsKpiStrip } from "@/app/agents/agents-kpi-strip";
import { OverviewAssets } from "@/components/overview-assets";
import type { InventorySummaryResponse } from "@/lib/api";
import { AGENT_COUNT_SCOPE } from "@/lib/count-scope";
import { ASSET_KIND_BY_ID } from "@/lib/inventory";

// One snapshot, three agent counts. The graph records 16 agent nodes (AI clients,
// background agents and cloud-managed agents); scans found 9 agent identities; the
// inventory card adds models, frameworks and datasets to the agent records.
const SNAPSHOT: InventorySummaryResponse = {
  schema_version: "inventory.summary.v1", tenant_id: "tenant-a", by_group: {}, finding_count: 0,
  facets: { type: { buckets: [] }, source: { buckets: [] }, provider: { buckets: [] }, environment: { buckets: [] }, severity: { buckets: [] } },
  facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: "snap-1" },
  completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 40, total: 40 },
  scan_id: "snap-1", total_assets: 40, by_type: { agent: 16, model: 5, framework: 2, dataset: 1, server: 16 },
};
const SCANNED = {
  agents: 9, configured: 9, not_configured: 0, mcp_servers: 12, remote_servers: 0, packages: 30,
  ecosystems: { npm: 30 }, unique_credentials: 2, servers_with_credentials: 2, blocked_servers: 0,
};

describe("agent counts across Overview, Agents and Asset inventory", () => {
  it("Overview counts graph agent records and says so", () => {
    render(<OverviewAssets summary={SNAPSHOT} />);

    const tile = screen.getByRole("link", { name: "16 Agents" });
    expect(tile).toHaveAttribute("title", AGENT_COUNT_SCOPE.snapshot.title);
  });

  it("the Agents page names its own population and shows the Overview number beside it, labelled", () => {
    render(<AgentsKpiStrip summary={SCANNED} classCounts={{ client: 6, background: 3 }} scope="scanned_estate" estateAgents={SNAPSHOT.by_type.agent ?? null} />);

    const kpis = within(screen.getByTestId("agents-kpis"));
    const tile = kpis.getByText(AGENT_COUNT_SCOPE.scanned.label).parentElement!.parentElement!;
    expect(within(tile).getByText("9")).toBeInTheDocument();
    expect(within(tile).getByText(`16 ${AGENT_COUNT_SCOPE.snapshot.caption}`)).toBeInTheDocument();
    expect(tile).toHaveAttribute("title", expect.stringContaining(AGENT_COUNT_SCOPE.scanned.title));
  });

  it("host discovery is labelled as this host, with the same snapshot caption", () => {
    render(<AgentsKpiStrip summary={{ ...SCANNED, agents: 5 }} classCounts={{ client: 2, background: 3 }} scope="local_discovery" estateAgents={16} />);

    const kpis = within(screen.getByTestId("agents-kpis"));
    expect(kpis.getByText(AGENT_COUNT_SCOPE.host.label)).toBeInTheDocument();
    expect(kpis.getByText(`16 ${AGENT_COUNT_SCOPE.snapshot.caption}`)).toBeInTheDocument();
  });

  it("the inventory card is AI entities, a wider set than agent records, never labelled as agents", () => {
    const card = ASSET_KIND_BY_ID.agents;
    const total = card.entityTypes.reduce((sum, type) => sum + (SNAPSHOT.by_type[type] ?? 0), 0);

    expect(card.label).toBe("AI entities");
    expect(card.label.toLowerCase()).not.toMatch(/^agents?$|ai agents/);
    expect(total).toBe(24);
    expect(total).toBeGreaterThanOrEqual(SNAPSHOT.by_type.agent ?? 0);
  });
});
