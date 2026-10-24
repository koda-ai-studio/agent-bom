import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScanResultView } from "@/components/scan-result";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getScanStatus: vi.fn(),
    getScan: vi.fn(),
    downloadScanGraph: vi.fn(),
  },
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    className,
  }: {
    href: string;
    children: React.ReactNode;
    className?: string;
  }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

vi.mock("@/components/scan-pipeline", () => ({
  ScanPipeline: ({ onStepClick }: { onStepClick?: (id: string) => void }) => (
    <button onClick={() => onStepClick?.("extraction")}>Inspect extraction</button>
  ),
}));

vi.mock("@/lib/use-scan-stream", () => ({
  useScanStream: () => ({
    messages: [],
    pipelineSteps: new Map(),
    streaming: false,
  }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: apiMock,
  };
});

describe("ScanResultView cloud evidence", () => {
  beforeEach(() => {
    Object.values(apiMock).forEach((mockFn) => mockFn.mockReset());
    apiMock.getScanStatus.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
    });
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: [],
        cloud_inventory: {
          provider: "aws",
          resource_count: 42,
          identity_count: 7,
        },
        cis_benchmark: {
          benchmark: "CIS AWS",
          benchmark_version: "1.5",
          passed: 30,
          failed: 10,
          total: 40,
          pass_rate: 0.75,
        },
      },
    });
  });

  it("renders persisted cloud inventory and CIS evidence even without attack-path findings", async () => {
    render(<ScanResultView id="scan-cloud-1" />);

    await waitFor(() => expect(apiMock.getScan).toHaveBeenCalledWith("scan-cloud-1"));

    expect(screen.getByText("Cloud evidence")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Cloud evidence" })).toHaveClass(
      "bg-surface",
      "dark:bg-cyan-950/20",
    );
    expect(screen.getByText("AWS")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("AWS CIS")).toBeInTheDocument();
    expect(screen.getByText("30/40 passed · 75%")).toBeInTheDocument();
    expect(
      screen.getByText(/Cloud inventory and posture evidence was persisted/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Continue from this scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Findings/i })).toHaveAttribute("href", "/findings?scan=scan-cloud-1");
    expect(screen.getByRole("link", { name: /Investigation/i })).toHaveAttribute(
      "href",
      "/security-graph?scan=scan-cloud-1&investigate=1&lens=attack-path",
    );
    expect(screen.getByText("Open graph evidence; no attack path is asserted")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Remediation/i })).toHaveAttribute("href", "/remediation?scan=scan-cloud-1");
  });

  it("reconciles every recorded ATLAS association without a detection denominator", async () => {
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1", status: "done", created_at: "2026-06-27T00:00:00Z", request: {},
      result: { agents: [], blast_radius: [{ vulnerability_id: "CVE-2026-1000", severity: "low",
        affected_agents: [], exposed_credentials: [], exposed_tools: [],
        atlas_tags: ["AML.T0037", "AML.T0037", "AML.T9999"], owasp_tags: [] }] },
    });
    render(<ScanResultView id="scan-cloud-1" />);
    const heading = await screen.findByRole("heading", { name: "MITRE ATLAS" });
    const panel = heading.closest("section")!;
    expect(within(panel).getByText("2 recorded associations")).toBeVisible();
    expect(within(panel).getByText("Data from Local System")).toBeVisible();
    expect(within(panel).getByText("AML.T9999")).toBeVisible();
    expect(within(panel).queryByText(/triggered/)).toBeNull();
    expect(within(panel).queryByText("Poison Training Data")).toBeNull();
  });

  it("filters and paginates dense blast-radius evidence instead of rendering every path", async () => {
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: Array.from({ length: 13 }, (_, index) => ({
          vulnerability_id: `CVE-2026-${String(index).padStart(4, "0")}`,
          package: `pkg-${index}`,
          severity: index % 2 === 0 ? "critical" : "high",
          blast_score: index,
          affected_agents: [],
          exposed_credentials: [],
          reachable_tools: [],
        })),
      },
    });

    const user = userEvent.setup();
    render(<ScanResultView id="scan-cloud-1" />);

    expect(await screen.findByText("Page 1 of 2 (13 paths)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Blast Radius \(13\)/i })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    expect(screen.getByText("CVE-2026-0012")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2026-0000")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("CVE-2026-0000")).toBeInTheDocument();

    await user.selectOptions(
      screen.getByRole("combobox", { name: "Filter blast-radius paths by severity" }),
      "critical",
    );
    expect(screen.getByText("Page 1 of 1 (7 paths)")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2026-0011")).not.toBeInTheDocument();
  });

  it("sums per-account counts for an organization fan-out inventory list", async () => {
    apiMock.getScan.mockResolvedValue({
      job_id: "scan-cloud-1",
      status: "done",
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:05:00Z",
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: [],
        cloud_inventory: [
          { provider: "aws", account_id: "111111111111", resource_count: 30, identity_count: 4 },
          { provider: "aws", account_id: "222222222222", resource_count: 12, identity_count: 3 },
        ],
      },
    });

    render(<ScanResultView id="scan-cloud-1" />);

    await waitFor(() => expect(apiMock.getScan).toHaveBeenCalledWith("scan-cloud-1"));

    // Resources is the estate total, not the member-account count (2).
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
  });
});


it("opens recorded stage details from the full scan and rolls up without another fetch", async () => {
  const user = userEvent.setup();
  const full = {
    job_id: "scan-interactive", status: "done", created_at: "2026-09-09T12:00:00Z",
    completed_at: "2026-09-09T12:00:10Z", request: {},
    progress: ["discovery", "extraction", "scanning", "enrichment", "analysis", "output"].map(step_id => JSON.stringify({
      type: "step", step_id, status: "done", message: `${step_id} complete`,
      started_at: "2026-09-09T12:00:00Z", completed_at: "2026-09-09T12:00:02Z",
      stats: step_id === "extraction" ? { packages: 1095 } : {},
    })), result: { agents: [], blast_radius: [], summary: { total_packages: 1095, total_vulnerabilities: 2 } },
  };
  apiMock.getScan.mockReset();
  apiMock.getScan.mockResolvedValue(full);
  apiMock.getScanStatus.mockResolvedValue(full);
  render(<ScanResultView id="scan-interactive" />);
  await user.click(await screen.findByRole("button", { name: "Inspect extraction" }));
  const detail = screen.getByRole("complementary", { name: "Stage details" });
  expect(detail).toHaveTextContent("extraction complete");
  expect(detail).toHaveTextContent("1095 packages");
  expect(detail).toHaveTextContent("2.0s");
  await user.click(screen.getByRole("button", { name: "Close stage detail" }));
  expect(screen.queryByRole("complementary", { name: "Stage details" })).not.toBeInTheDocument();
  expect(apiMock.getScan).toHaveBeenCalledTimes(1);
});

it("labels the credentials the hosting servers hold apart from exposure by impact in the scan's plan", async () => {
  const planItem = {
    package: "requests", ecosystem: "pypi", current_version: "2.28.0", fixed_version: "2.31.0", severity: "medium",
    is_kev: false, impact_score: 4, vulnerabilities: ["CVE-2023-32681"], affected_agents: ["a"], agents_pct: 100,
    exposed_credentials: ["DATABASE_URL"], credentials_pct: 100, reachable_tools: [], tools_pct: 0,
    owasp_tags: [], atlas_tags: [], risk_narrative: "narrative",
  };
  apiMock.getScanStatus.mockResolvedValue({ job_id: "scan-plan", status: "done", created_at: "2026-06-27T00:00:00Z", request: {} });
  apiMock.getScan.mockResolvedValue({
    job_id: "scan-plan", status: "done", created_at: "2026-06-27T00:00:00Z", request: {},
    result: { agents: [], blast_radius: [], remediation_plan: [
      { ...planItem, server_credentials: ["DATABASE_URL", "STRIPE_KEY"], server_credential_count: 2 },
      { ...planItem, package: "unrecorded", server_credential_count: null },
    ] },
  });
  render(<ScanResultView id="scan-plan" />);
  const held = await screen.findByText("2 credentials on server");
  expect(held.getAttribute("title")).toMatch(/hosting servers hold.*not filtered by this advisory's impact/);
  expect(screen.getAllByText(/credentials? on server/)).toHaveLength(1);
});
