import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AgentsKpiStrip } from "@/app/agents/agents-kpi-strip";
import { OverviewAssets } from "@/components/overview-assets";
import type { InventorySummaryResponse } from "@/lib/api";
import { PACKAGE_COUNT_SCOPE } from "@/lib/count-scope";
import { ASSET_KIND_BY_ID } from "@/lib/inventory";
import { kindCardLabel, kindHeadline, kindUnit } from "@/lib/inventory-units";

// One snapshot, two package populations: 1,137 distinct package records in the graph, and
// 1,314 package entries summed per agent (npm 772 + pypi 494 + github-action 31 + go 15 + conda 2),
// because a package several agents declare counts once per agent.
const SNAPSHOT: InventorySummaryResponse = {
  schema_version: "inventory.summary.v1", tenant_id: "tenant-a", by_group: {}, finding_count: 0,
  facets: { type: { buckets: [] }, source: { buckets: [] }, provider: { buckets: [] }, environment: { buckets: [] }, severity: { buckets: [] } },
  facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: "snap-1" },
  completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 1200, total: 1200 },
  scan_id: "snap-1", total_assets: 1200, by_type: { agent: 4, package: 1137 },
};
const ECOSYSTEMS = { npm: 772, pypi: 494, "github-action": 31, go: 15, conda: 2 };
const AGENTS = {
  agents: 4, configured: 4, not_configured: 0, mcp_servers: 6, remote_servers: 0,
  packages: Object.values(ECOSYSTEMS).reduce((sum, count) => sum + count, 0),
  ecosystems: ECOSYSTEMS, unique_credentials: 0, servers_with_credentials: 0, blocked_servers: 0,
};

describe("package counts for one snapshot", () => {
  it("each surface names the population it counts, so 1,314 and 1,137 never read as one number", () => {
    expect(AGENTS.packages).toBe(1314);

    render(<AgentsKpiStrip summary={AGENTS} classCounts={{ client: 4, background: 0 }} scope="scanned_estate" estateAgents={4} />);
    const kpis = within(screen.getByTestId("agents-kpis"));
    const references = kpis.getByText(PACKAGE_COUNT_SCOPE.references.label).parentElement!.parentElement!;
    expect(within(references).getByText("1,314")).toBeInTheDocument();
    expect(within(references).getByText(new RegExp(`^${PACKAGE_COUNT_SCOPE.references.caption}`))).toBeInTheDocument();
    expect(references).toHaveAttribute("title", PACKAGE_COUNT_SCOPE.references.title);
    expect(kpis.queryByText("Packages")).toBeNull();

    render(<OverviewAssets summary={SNAPSHOT} />);
    expect(screen.getByRole("link", { name: `1,137 ${PACKAGE_COUNT_SCOPE.unique.label}` })).toHaveAttribute("title", PACKAGE_COUNT_SCOPE.unique.title);

    const kind = ASSET_KIND_BY_ID.packages;
    const { primary, breakdown } = kindHeadline(kind, SNAPSHOT.by_type);
    expect(primary).toBe(1137);
    expect(kindUnit(kind, primary)).toBe(PACKAGE_COUNT_SCOPE.unique.label);
    expect(kindCardLabel(kind, primary, breakdown, "in snapshot")).toBe(`Packages: 1,137 ${PACKAGE_COUNT_SCOPE.unique.label}, in snapshot`);

    expect(PACKAGE_COUNT_SCOPE.references.label).not.toBe(PACKAGE_COUNT_SCOPE.unique.label);
  });
});
