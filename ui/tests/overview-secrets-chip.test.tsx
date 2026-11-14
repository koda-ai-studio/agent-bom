import { render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Dashboard from "@/app/page";
import FindingsPage from "@/app/findings/page";
import { SeverityIssueStrip } from "@/components/overview/issue-strip";
import type { OverviewResponse } from "@/lib/api";

const { apiMock, navigationState } = vi.hoisted(() => ({
  navigationState: { query: "" },
  apiMock: {
    getInventorySummary: vi.fn(),
    getPosture: vi.fn(),
    getOverview: vi.fn(),
    getTrends: vi.fn(),
    getCompliance: vi.fn(),
    listJobs: vi.fn(),
    listAgents: vi.fn(),
    getScanDashboard: vi.fn(),
    updateScoreConfig: vi.fn(),
    listFindings: vi.fn(),
    listFindingTriage: vi.fn(),
    getPostureCounts: vi.fn(),
  },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(navigationState.query),
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/findings",
}));
vi.mock("next/link", () => ({
  default: ({ href, children, title, className }: { href: string; children: ReactNode; title?: string; className?: string }) => (
    <a href={href} title={title} className={className}>{children}</a>
  ),
}));
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});
vi.mock("@/hooks/use-deployment-context", () => ({
  useDeploymentContext: () => ({ counts: { critical: 1, high: 1, medium: 0, low: 0, total: 2, kev: 0, compound_issues: 0, scan_count: 1, services: {} }, loading: false, error: null }),
}));
vi.mock("@/lib/use-capture-mode", () => ({ useCaptureMode: () => false }));
vi.mock("@/components/activity-feed", () => ({ ActivityFeed: () => <div>Activity fixture</div> }));
vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({ session: { auth_required: false, role: "viewer" }, hasCapability: () => false }),
}));

// Filters that change which rows match; paging, sort and facet flags do not change a total.
const PAGING_ONLY = new Set(["limit", "offset", "cursor", "sort", "includeFacets", "approximateTotal"]);

/** One fixture estate: the total depends on every filter that selects rows, so a differing query shows a different number. */
function fixtureTotal(filters: Record<string, unknown>): number {
  const selecting = Object.entries(filters).filter(([key, value]) => !PAGING_ONLY.has(key) && value !== undefined).sort(([a], [b]) => a.localeCompare(b));
  let hash = 7;
  for (const char of JSON.stringify(selecting)) hash = (hash * 31 + char.charCodeAt(0)) % 997;
  return hash + 1;
}

function overviewFixture(): OverviewResponse {
  const domain = (label: string) => ({ label, href: "/", metric: 0, metric_label: "", status: "ok" as const, detail: {} });
  return {
    schema_version: "overview.v1",
    tenant_id: "tenant-ui",
    posture: { grade: "C", score: 70, summary: "", breakdown: [], display_format: "percent" as const },
    // A different population (findings on servers holding credentials); the chip must not show it.
    headline: { critical: 1, high: 1, critical_high: 2, kev: 0, credential_exposed: 24, scans: 1, latest_scan_at: "2026-11-01T00:00:00Z" },
    domains: { cloud: domain("Cloud"), vuln: domain("Vuln"), code: domain("Code"), runtime: domain("Runtime"), cost: domain("Cost"), identity: domain("Identity"), ops: domain("Ops") },
    coverage: [],
    top_risks: [],
  };
}

describe("Overview Secrets chip", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigationState.query = "";
    apiMock.getInventorySummary.mockResolvedValue(null);
    apiMock.getPosture.mockResolvedValue({ grade: "C", score: 70 });
    apiMock.getOverview.mockResolvedValue(overviewFixture());
    apiMock.getTrends.mockResolvedValue({ tenant_id: "tenant-ui", count: 0, points: [] });
    apiMock.getCompliance.mockRejectedValue(new Error("not configured"));
    apiMock.listJobs.mockResolvedValue({ jobs: [] });
    apiMock.listAgents.mockResolvedValue({ count: 0, agents: [] });
    apiMock.getScanDashboard.mockResolvedValue(null);
    apiMock.listFindingTriage.mockResolvedValue({ triage: [] });
    apiMock.getPostureCounts.mockResolvedValue({ critical: 0, high: 0, medium: 0, low: 0, total: 0, kev: 0, compound_issues: 0 });
    apiMock.listFindings.mockImplementation(async (filters: Record<string, unknown>) => ({
      schema_version: "v1", findings: [], total: fixtureTotal(filters), has_more: false, next_cursor: "",
    }));
  });

  it("shows the same total as the Findings view it links to", async () => {
    render(<Dashboard />);
    const chip = await screen.findByRole("link", { name: /^Secrets \d+$/ });
    const href = chip.getAttribute("href") ?? "";
    expect(href).toBe("/findings?scope=all&issue=secret");
    const chipValue = Number(/(\d+)$/.exec(chip.textContent ?? "")?.[1]);
    expect(chipValue).not.toBe(24);

    apiMock.listFindings.mockClear();
    navigationState.query = new URL(href, "http://x").searchParams.toString();
    render(<FindingsPage />);
    await waitFor(() => expect(apiMock.listFindings).toHaveBeenCalled());
    const linkedTotal = (await apiMock.listFindings.mock.results[0]!.value).total as number;
    expect(apiMock.listFindings.mock.calls[0]![0]).toMatchObject({ findingClass: "secret" });
    expect(chipValue).toBe(linkedTotal);
  });

  it("names an imported report's credential-exposed count for what it is and does not link it to secret findings", () => {
    render(
      <SeverityIssueStrip
        summaryReady critical={0} high={0} kev={null} credentials={3} credentialsPopulation="credential_exposed"
        severity={{ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } as never} matrix={null}
      />,
    );
    expect(screen.getByText("Credential-exposed 3")).toBeInTheDocument();
    expect(screen.queryByText(/^Secrets/)).toBeNull();
    expect(screen.queryByRole("link", { name: /Credential-exposed/ })).toBeNull();
  });
});
