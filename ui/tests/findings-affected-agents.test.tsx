import { fireEvent, render, screen, within } from "@testing-library/react";
import { expect, it, vi } from "vitest";

import { FindingsQueueTable } from "@/components/findings-queue";
import type { EnrichedVuln } from "@/lib/findings-view";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => false }) }));
vi.mock("@/lib/asset-base", () => ({ ASSET_BASE: "" }));

function row(overrides: Partial<EnrichedVuln> = {}): EnrichedVuln {
  return {
    id: "CVE-2026-1234", severity: "critical", summary: "Fixture", packages: ["requests"], current_version: "2.0", agents: [],
    sources: ["SBOM"], advisory_sources: ["OSV"], affected_servers: [], exposed_credentials: [], reachable_tools: [],
    references: [], remediation_items: [], ...overrides,
  };
}

function mount(vuln: EnrichedVuln, onSelect = vi.fn()) {
  render(
    <FindingsQueueTable columnProfile="all" vulns={[vuln]} sortKey="severity" sortDir="desc" handleSort={vi.fn()}
      pendingExceptions={new Set()} onMarkFP={vi.fn()} selectedId={null} onSelect={onSelect} />,
  );
  return screen.getByTestId("finding-affected-agents");
}

const forty = Array.from({ length: 40 }, (_, index) => `team-agent-${index + 1}`);

it("shows the first two agents and a remainder counted from every affected agent", () => {
  const cell = mount(row({ agents: forty }));
  expect(within(cell).getByRole("link", { name: "Team Agent 1" })).toBeInTheDocument();
  expect(within(cell).getByRole("link", { name: "Team Agent 2" })).toBeInTheDocument();
  expect(within(cell).queryByRole("link", { name: "Team Agent 3" })).not.toBeInTheDocument();
  const more = within(cell).getByRole("link", { name: "All 40 affected agents for CVE-2026-1234" });
  expect(more.textContent).toBe("+38 more");
  expect(more).toHaveAttribute("href", "/advisories?id=CVE-2026-1234");
});

it("separates agents structurally so a wrapped line never starts with a comma", () => {
  const cell = mount(row({ agents: forty }));
  expect(cell.tagName).toBe("UL");
  const items = within(cell).getAllByRole("listitem");
  expect(items).toHaveLength(3);
  for (const item of items) expect(item.textContent?.trim().startsWith(",")).toBe(false);
  expect(cell.textContent).not.toContain(",");
});

it("shows no remainder when two or fewer agents are affected", () => {
  const cell = mount(row({ agents: ["a-one", "a-two"] }));
  expect(within(cell).getAllByRole("listitem")).toHaveLength(2);
  expect(within(cell).queryByText(/more/)).not.toBeInTheDocument();
});

it("opens the finding drawer for the remainder when the id is not an advisory", () => {
  const onSelect = vi.fn();
  const cell = mount(row({ id: "misconfig-public-bucket", agents: ["a", "b", "c"] }), onSelect);
  const more = within(cell).getByRole("button", { name: "All 3 affected agents for misconfig-public-bucket" });
  expect(more.textContent).toBe("+1 more");
  fireEvent.click(more);
  expect(onSelect).toHaveBeenCalled();
});

it("says a budget-limited row was not assessed instead of leaving the reach cell blank", () => {
  render(
    <FindingsQueueTable columnProfile="vulnerabilities" sortKey="severity" sortDir="desc" handleSort={vi.fn()}
      vulns={[row({ graph_reachable: null, epss_score: 0.4, graph_reachability_not_assessed_reason: "path_budget" })]}
      pendingExceptions={new Set()} onMarkFP={vi.fn()} selectedId={null} onSelect={vi.fn()} />,
  );
  const badge = screen.getByText("Not assessed (budget)");
  expect(badge).toHaveAttribute("title", expect.stringContaining("budget"));
});

it("says a refreshing graph left the row unassessed", () => {
  render(
    <FindingsQueueTable columnProfile="vulnerabilities" sortKey="severity" sortDir="desc" handleSort={vi.fn()}
      vulns={[row({ graph_reachable: null, graph_reachability_not_assessed_reason: "graph_refreshing" })]}
      pendingExceptions={new Set()} onMarkFP={vi.fn()} selectedId={null} onSelect={vi.fn()} />,
  );
  expect(screen.getByText("Not assessed (refreshing)")).toBeInTheDocument();
});

it("names the remainder on the phone card instead of cutting the asset list to two", () => {
  vi.stubGlobal("matchMedia", (query: string) => ({ matches: true, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  try {
    render(
      <FindingsQueueTable columnProfile="all" vulns={[row({ agents: forty })]} sortKey="severity" sortDir="desc" handleSort={vi.fn()}
        pendingExceptions={new Set()} onMarkFP={vi.fn()} selectedId={null} onSelect={vi.fn()} />,
    );
    expect(screen.getByText("requests@2.0, team-agent-1 +39 more")).toBeInTheDocument();
  } finally {
    vi.unstubAllGlobals();
  }
});

it("names the budget on the phone card reach field", () => {
  vi.stubGlobal("matchMedia", (query: string) => ({ matches: true, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  try {
    render(
      <FindingsQueueTable columnProfile="vulnerabilities" sortKey="severity" sortDir="desc" handleSort={vi.fn()}
        vulns={[row({ graph_reachable: null, epss_score: 0.4, graph_reachability_not_assessed_reason: "path_budget" })]}
        pendingExceptions={new Set()} onMarkFP={vi.fn()} selectedId={null} onSelect={vi.fn()} />,
    );
    expect(screen.getByText("Not assessed (budget) · EPSS 40.0%")).toBeInTheDocument();
  } finally {
    vi.unstubAllGlobals();
  }
});
