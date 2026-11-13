import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AssetInventoryView } from "@/components/inventory/asset-inventory-view";
import { InventoryIndex } from "@/components/inventory/inventory-index";
import { api } from "@/lib/api";
import type { InventoryAsset, InventoryAssetsResponse, InventoryFacets, InventorySummaryResponse } from "@/lib/api";
import { InventoryProvider } from "@/lib/inventory-context";
import { ASSET_KINDS, ASSET_KIND_BY_ID } from "@/lib/inventory";
import { entityTypeLabel, kindHeadline, kindTypeCounts } from "@/lib/inventory-units";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: { ...actual.api, getInventorySummary: vi.fn(), getInventoryAssets: vi.fn(), getInventoryAsset: vi.fn(), getGraph: vi.fn() },
  };
});

const SNAPSHOT = "scan-units-1";
const MIXED: Record<string, number> = {
  server: 12, tool: 312, tool_call: 1204,
  agent: 5, model: 4, framework: 2,
  cloud_resource: 40, data_store: 10, account: 3, provider: 1,
  user: 7, role: 9, credential_ref: 2,
  package: 700,
};

function facets(byType: Record<string, number>): InventoryFacets {
  return {
    type: { buckets: Object.entries(byType).map(([value, count]) => ({ value, count })) },
    source: { buckets: [] }, provider: { buckets: [] }, environment: { buckets: [] }, severity: { buckets: [] },
  };
}

function summary(byType: Record<string, number>, typeFacet: Record<string, number> = byType): InventorySummaryResponse {
  const total = Object.values(byType).reduce((a, b) => a + b, 0);
  return {
    schema_version: "inventory.summary.v1", tenant_id: "tenant-a", scan_id: SNAPSHOT, created_at: "2026-11-01T00:00:00Z",
    total_assets: total, by_type: byType, by_group: {}, finding_count: 0, facets: facets(typeFacet),
    facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: SNAPSHOT },
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: total, total },
  };
}

function row(id: string, type: string): InventoryAsset {
  return {
    id, type, name: id, environment: "", provider: "", risk: 0, severity: "none", status: "active", source: "local",
    sources: ["local"], first_seen: "", last_seen: "", attributes: {}, compliance_tags: [], ecosystem: "", version: "",
    finding_summary: { total: 0, by_severity: {}, ids: [], top_severity: "" }, relationship_count: 0,
  };
}

function page(assets: InventoryAsset[], total: number): InventoryAssetsResponse {
  return {
    schema_version: "inventory.assets.v1", tenant_id: "tenant-a", scan_id: SNAPSHOT, created_at: "2026-11-01T00:00:00Z",
    assets, filters: {}, pagination: { total, offset: 0, limit: 100, next_cursor: "", has_more: false, facet_filtered: false },
    facets: facets(MIXED), facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: SNAPSHOT },
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: assets.length, total },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getInventorySummary).mockResolvedValue(summary(MIXED));
  vi.mocked(api.getInventoryAssets).mockResolvedValue(page([row("srv-a", "server"), row("tool-a", "tool"), row("call-a", "tool_call")], 1528));
});

describe("asset kind units", () => {
  it("declares a primary unit inside every kind's entity types", () => {
    for (const kind of ASSET_KINDS) {
      expect(kind.primaryTypes.length).toBeGreaterThan(0);
      for (const type of kind.primaryTypes) expect(kind.entityTypes).toContain(type);
      expect(kind.unitLabel).toBeTruthy();
    }
    expect(ASSET_KIND_BY_ID.servers.primaryTypes).toEqual(["server"]);
    expect(ASSET_KIND_BY_ID.agents.primaryTypes).toEqual(["agent"]);
    for (const scope of ["account", "org", "environment", "provider", "cluster", "fleet"]) {
      expect(ASSET_KIND_BY_ID.cloud.primaryTypes).not.toContain(scope);
    }
  });

  it("counts only the primary unit in the headline and lists the other types separately", () => {
    const servers = kindHeadline(ASSET_KIND_BY_ID.servers, MIXED);
    expect(servers.primary).toBe(12);
    expect(servers.breakdown.map((part) => [part.type, part.count, part.label])).toEqual([
      ["tool_call", 1204, "tool calls"],
      ["tool", 312, "tools"],
    ]);
    const cloud = kindHeadline(ASSET_KIND_BY_ID.cloud, MIXED);
    expect(cloud.primary).toBe(50);
    expect(cloud.breakdown.map((part) => part.type)).toEqual(["account", "provider"]);
    expect(kindHeadline(ASSET_KIND_BY_ID.packages, MIXED).breakdown).toEqual([]);
  });

  it("omits zero parts and pluralizes per count", () => {
    const one = kindHeadline(ASSET_KIND_BY_ID.servers, { server: 0, tool: 1, tool_call: 0 });
    expect(one.primary).toBe(0);
    expect(one.breakdown).toEqual([{ type: "tool", count: 1, label: "tool" }]);
    expect(entityTypeLabel("policy", 2)).toBe("policies");
    expect(entityTypeLabel("ci_job", 1)).toBe("CI job");
  });

  it("reads per-type kind counts from the self-excluding type facet so a type filter does not hide siblings", () => {
    const filtered = summary({ tool: 312 }, MIXED);
    expect(kindTypeCounts(ASSET_KIND_BY_ID.servers, filtered)).toEqual([
      { type: "server", count: 12 }, { type: "tool", count: 312 }, { type: "tool_call", count: 1204 },
    ]);
  });
});

describe("inventory cards", () => {
  it("headlines MCP servers only, with tools and tool calls as a breakdown", async () => {
    render(<InventoryProvider><InventoryIndex /></InventoryProvider>);
    await screen.findByRole("link", { name: /MCP servers/ });
    await waitFor(() => assertCards());
  });
});

function assertCards() {
  {
    const card = screen.getByRole("link", { name: /MCP servers/ });
    expect(within(card).getByText("12")).toBeInTheDocument();
    expect(within(card).queryByText("1,528")).not.toBeInTheDocument();
    expect(within(card).getByText("1,204 tool calls · 312 tools")).toBeInTheDocument();
    expect(card).toHaveAccessibleName("Servers & tools: 12 MCP servers, plus 1,204 tool calls and 312 tools, in snapshot");

    const agents = screen.getByRole("link", { name: /AI agents/ });
    expect(within(agents).getByText("5")).toBeInTheDocument();
    expect(within(agents).getByText("4 models · 2 frameworks")).toBeInTheDocument();
    const cloud = screen.getByRole("link", { name: /Cloud resources:/ });
    expect(within(cloud).getByText("50")).toBeInTheDocument();
    expect(within(cloud).getByText("3 accounts · 1 provider")).toBeInTheDocument();
    const identity = screen.getByRole("link", { name: /Identity & access:/ });
    expect(within(identity).getByText("7")).toBeInTheDocument();
    expect(within(identity).getByText("9 roles · 2 credential references")).toBeInTheDocument();
  }
}

describe("kind list type chips", () => {
  function renderServers() {
    return render(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.servers.entityTypes} scanId={SNAPSHOT}>
        <AssetInventoryView kind="servers" />
      </InventoryProvider>,
    );
  }

  it("offers per-type chips whose counts match the card headline and breakdown", async () => {
    renderServers();
    const chips = await screen.findByRole("group", { name: "Filter by asset type" });
    expect(within(chips).getByRole("button", { name: "All types 1,528" })).toHaveAttribute("aria-pressed", "true");
    const server = within(chips).getByRole("button", { name: "MCP servers 12" });
    expect(server).toHaveAttribute("aria-pressed", "false");
    const headline = kindHeadline(ASSET_KIND_BY_ID.servers, MIXED);
    expect(within(chips).getByRole("button", { name: `MCP servers ${headline.primary}` })).toBe(server);
    for (const part of headline.breakdown) {
      const plural = entityTypeLabel(part.type, 2);
      const name = `${plural.charAt(0).toUpperCase()}${plural.slice(1)} ${part.count.toLocaleString()}`;
      expect(within(chips).getByRole("button", { name })).toBeInTheDocument();
    }
    expect(screen.queryByLabelText("Filter by type")).not.toBeInTheDocument();
  });

  it("shows each row's type under a neutral Name column", async () => {
    renderServers();
    const table = await screen.findByTestId("inventory-table-servers");
    expect(within(table).getByRole("columnheader", { name: "Name" })).toBeInTheDocument();
    expect(within(table).getByRole("columnheader", { name: "Type" })).toBeInTheDocument();
    expect(within(table).queryByRole("columnheader", { name: "Server" })).not.toBeInTheDocument();
    expect(within(table).getByText("Tool call")).toBeInTheDocument();
    expect(within(table).getByText("MCP server")).toBeInTheDocument();
  });

  it("filters to one type from a chip and keeps sibling counts", async () => {
    renderServers();
    const chips = await screen.findByRole("group", { name: "Filter by asset type" });
    vi.mocked(api.getInventorySummary).mockResolvedValue(summary({ tool: 312 }, MIXED));
    fireEvent.click(within(chips).getByRole("button", { name: "Tools 312" }));
    await waitFor(() => expect(api.getInventorySummary).toHaveBeenLastCalledWith(SNAPSHOT, expect.objectContaining({ type: ["tool"] })));
    await waitFor(() => expect(screen.getByRole("button", { name: "Tools 312" })).toHaveAttribute("aria-pressed", "true"));
    expect(screen.getByRole("button", { name: "MCP servers 12" })).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(screen.getByRole("button", { name: "All types 1,528" }));
    await waitFor(() => expect(api.getInventorySummary).toHaveBeenLastCalledWith(SNAPSHOT, expect.objectContaining({ type: ASSET_KIND_BY_ID.servers.entityTypes })));
  });
});

describe("kind page follow-ups", () => {
  function renderServers() {
    return render(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.servers.entityTypes} scanId={SNAPSHOT}>
        <AssetInventoryView kind="servers" />
      </InventoryProvider>,
    );
  }

  function looksActive(chip: HTMLElement): boolean {
    return chip.className.split(/\s+/).some((token) => token.startsWith("bg-[color:var(--accent-soft"));
  }

  it("styles exactly one chip as active, and hover or focus never borrows the active look", async () => {
    renderServers();
    const chips = await screen.findByRole("group", { name: "Filter by asset type" });
    const check = (activeName: string) => {
      const buttons = within(screen.getByRole("group", { name: "Filter by asset type" })).getAllByRole("button");
      expect(buttons.filter((b) => b.getAttribute("aria-pressed") === "true").map((b) => b.getAttribute("aria-label"))).toEqual([activeName]);
      expect(buttons.filter(looksActive).map((b) => b.getAttribute("aria-label"))).toEqual([activeName]);
      for (const button of buttons.filter((b) => !looksActive(b))) {
        expect(button.className).not.toMatch(/(hover|focus|focus-visible|active):bg-/);
      }
    };
    check("All types 1,528");
    vi.mocked(api.getInventorySummary).mockResolvedValue(summary({ tool: 312 }, MIXED));
    fireEvent.click(within(chips).getByRole("button", { name: "Tools 312" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Tools 312" })).toHaveAttribute("aria-pressed", "true"));
    check("Tools 312");
  });

  it("pluralizes every All option in the filter selects", async () => {
    render(<InventoryProvider><InventoryIndex /></InventoryProvider>);
    await screen.findByLabelText("Filter by environment");
    const allOptions = () => [...document.querySelectorAll("select option[value='']")].map((option) => option.textContent);
    await waitFor(() => expect(allOptions()).toHaveLength(5));
    expect(allOptions().sort()).toEqual(["All environments", "All finding severities", "All providers", "All sources", "All types"]);
  });

  it("shows one matching count unfiltered and adds the all-types count only when a type narrows it", async () => {
    renderServers();
    const stats = await screen.findByTestId("inventory-kind-stats");
    await waitFor(() => expect(within(stats).getAllByText("1,528")).toHaveLength(1));
    expect(within(stats).queryByText("Matching filters")).not.toBeInTheDocument();

    vi.mocked(api.getInventorySummary).mockResolvedValue(summary({ tool: 312 }, MIXED));
    vi.mocked(api.getInventoryAssets).mockResolvedValue(page([row("tool-a", "tool")], 312));
    fireEvent.click(screen.getByRole("button", { name: "Tools 312" }));
    await waitFor(() => expect(within(screen.getByTestId("inventory-kind-stats")).getByText("Matching filters")).toBeInTheDocument());
    const narrowed = screen.getByTestId("inventory-kind-stats");
    expect(within(narrowed).getByText("312")).toBeInTheDocument();
    expect(within(narrowed).getByText("All types")).toBeInTheDocument();
    expect(within(narrowed).getByText("1,528")).toBeInTheDocument();
  });
});
