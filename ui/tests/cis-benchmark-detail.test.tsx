import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CISBenchmarkDetail } from "@/components/cis-benchmark-detail";
import type { CISBenchmarkCheck } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listCisBenchmarkChecks: vi.fn(),
    searchGraph: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({
  api: apiMock,
}));

function makeCheck(overrides: Partial<CISBenchmarkCheck>): CISBenchmarkCheck {
  return {
    scan_id: "scan-1",
    measured_at: "2026-06-24T00:00:00Z",
    cloud: "aws",
    check_id: "1.1",
    title: "Maintain current contact details",
    status: "fail",
    severity: "medium",
    cis_section: "1 - Identity and Access Management",
    evidence: "Contact info incomplete",
    resource_ids: [],
    remediation: {},
    fix_cli: "",
    fix_console: "",
    effort: "manual",
    priority: 0,
    guardrails: [],
    requires_human_review: false,
    ...overrides,
  };
}

const writeText = vi.fn().mockResolvedValue(undefined);

beforeEach(() => {
  apiMock.listCisBenchmarkChecks.mockReset();
  apiMock.searchGraph.mockReset();
  apiMock.searchGraph.mockResolvedValue({ query: "", results: [], pagination: { total: 0, offset: 0, limit: 5, has_more: false } });
  writeText.mockClear();
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("CISBenchmarkDetail", () => {
  it("shows a loading state before checks resolve", () => {
    apiMock.listCisBenchmarkChecks.mockReturnValue(new Promise(() => {}));
    render(<CISBenchmarkDetail />);
    expect(screen.getByText(/loading cloud cis benchmark checks/i)).toBeInTheDocument();
  });

  it("renders an empty state when no checks exist", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({ checks: [], count: 0, source: "scan_jobs" });
    render(<CISBenchmarkDetail />);
    expect(await screen.findByText(/no cloud security checks yet/i)).toBeInTheDocument();
  });

  it("renders an error state with the fallback copy when the fetch fails opaquely", async () => {
    // An empty-message failure exercises the fallback string in the error UI.
    apiMock.listCisBenchmarkChecks.mockRejectedValue(new Error(""));
    render(<CISBenchmarkDetail />);
    expect(await screen.findByText(/could not load cloud cis benchmark checks/i)).toBeInTheDocument();
  });

  it("surfaces the underlying error message when one is present", async () => {
    apiMock.listCisBenchmarkChecks.mockRejectedValue(new Error("backend unavailable"));
    render(<CISBenchmarkDetail />);
    expect(await screen.findByText(/backend unavailable/i)).toBeInTheDocument();
  });

  it("renders all statuses by default so unevaluable checks are never hidden", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({ check_id: "1.4", title: "Eliminate root access keys", priority: 1, guardrails: ["identity"] }),
        makeCheck({ check_id: "3.1", title: "Ensure CloudTrail enabled", status: "pass" }),
        makeCheck({ check_id: "4.1", title: "Account usage unavailable", status: "error" }),
      ],
      count: 3,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    expect(await screen.findByText("Eliminate root access keys")).toBeInTheDocument();
    expect(screen.getByText("1.4")).toBeInTheDocument();
    expect(screen.getByText("Ensure CloudTrail enabled")).toBeInTheDocument();
    expect(screen.getByText("Account usage unavailable")).toBeInTheDocument();
    expect(screen.getByText(/3 of 3 checks shown/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Error" })).toBeInTheDocument();
  });

  it("copies a reviewed fix_cli and warns before use", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({
          check_id: "3.2",
          title: "Enable CloudTrail log file validation",
          fix_cli: "aws cloudtrail update-trail --name <TRAIL_NAME_OR_ARN> --enable-log-file-validation",
          requires_human_review: true,
          remediation: {
            fix_cli: "aws cloudtrail update-trail --name <TRAIL_NAME_OR_ARN> --enable-log-file-validation",
            requires_human_review: true,
          },
        }),
      ],
      count: 1,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    await screen.findByText("Enable CloudTrail log file validation");
    // Human-review badge is visible on a check that can break production.
    expect(screen.getByTestId("human-review-badge")).toBeInTheDocument();

    const copyButton = screen.getByRole("button", { name: /copy fix command/i });
    fireEvent.click(copyButton);
    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(
        "aws cloudtrail update-trail --name <TRAIL_NAME_OR_ARN> --enable-log-file-validation",
      ),
    );
    expect(await screen.findByText(/review carefully before running/i)).toBeInTheDocument();
  });

  it("renders fail-closed remediation as manual guidance", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({
          check_id: "1.4",
          title: "No root account access keys",
          fix_cli: "",
          fix_console: "AWS Organizations → Root access management, or approved break-glass root session → sign out immediately",
          effort: "manual",
          requires_human_review: true,
        }),
      ],
      count: 1,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    expect(await screen.findByText(/no copy-pasteable cli fix/i)).toBeInTheDocument();
    expect(screen.getByText(/approved break-glass root session/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /copy fix command/i })).not.toBeInTheDocument();
  });

  it("filters across all fetched checks by guardrail", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({ check_id: "1.4", title: "Root keys", guardrails: ["identity"] }),
        makeCheck({ check_id: "4.1", title: "Logging on", guardrails: ["logging-and-audit"] }),
      ],
      count: 2,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    await screen.findByText("Root keys");
    expect(screen.getByText("Logging on")).toBeInTheDocument();

    // Picking a guardrail narrows to checks carrying it, across every cloud.
    fireEvent.click(screen.getByRole("button", { name: "logging-and-audit" }));
    await waitFor(() => expect(screen.queryByText("Root keys")).not.toBeInTheDocument());
    expect(screen.getByText("Logging on")).toBeInTheDocument();
  });

  it("shows the cloud selector only for clouds present in the data", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({ cloud: "aws", check_id: "1.1", title: "AWS check" }),
        makeCheck({ cloud: "gcp", check_id: "2.1", title: "GCP check" }),
      ],
      count: 2,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    await screen.findByText("AWS check");
    const filters = screen.getByText("Cloud").closest("div") as HTMLElement;
    expect(within(filters).getByRole("button", { name: "AWS" })).toBeInTheDocument();
    expect(within(filters).getByRole("button", { name: "GCP" })).toBeInTheDocument();
    expect(within(filters).queryByRole("button", { name: "Azure" })).not.toBeInTheDocument();
  });

  it("gives each check exactly one status; the review flag belongs to a fix", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({ check_id: "1.20", title: "Analyzer enabled", status: "pass", requires_human_review: true }),
        makeCheck({ check_id: "4.1", title: "No open SSH", status: "fail", requires_human_review: true, fix_console: "EC2 > Security groups" }),
      ],
      count: 2, source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);
    const passCard = (await screen.findByText("Analyzer enabled")).closest("[data-testid='cis-check']") as HTMLElement;
    const passBadges = within(passCard).getAllByTestId("cis-check-status");
    expect(passBadges.map((badge) => badge.textContent)).toEqual(["Pass"]);
    expect(within(passCard).queryByText(/review/i)).toBeNull();
    const failCard = screen.getByText("No open SSH").closest("[data-testid='cis-check']") as HTMLElement;
    expect(within(failCard).getAllByTestId("cis-check-status").map((badge) => badge.textContent)).toEqual(["Fail"]);
    expect(within(failCard).getByText("Fix requires human review before applying")).toBeInTheDocument();
  });

  it("links a failing check's resources to the graph and their findings", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [makeCheck({ check_id: "2.1.5", title: "Block public access", status: "fail", resource_ids: ["customer-pii-prod"] })],
      count: 1, source: "scan_jobs",
    });
    apiMock.searchGraph.mockResolvedValue({
      query: "customer-pii-prod",
      results: [
        { id: "misconfig:showcase:pii-public", entity_type: "misconfiguration", label: "S3 bucket customer-pii-prod is publicly readable" },
        { id: "cloud:pii-bucket", entity_type: "cloud_resource", label: "customer-pii-prod (S3)" },
      ],
      pagination: { total: 2, offset: 0, limit: 5, has_more: false },
    });
    render(<CISBenchmarkDetail />);
    const list = await screen.findByRole("list", { name: "Resources failing 2.1.5" });
    const graph = await within(list).findByRole("link", { name: "Open customer-pii-prod (S3) in the graph" });
    expect(graph).toHaveAttribute("href", "/security-graph?lens=lineage&investigate=1&root=cloud%3Apii-bucket&node=cloud%3Apii-bucket");
    expect(within(list).getByRole("link", { name: "Findings on customer-pii-prod" })).toHaveAttribute("href", "/findings?q=customer-pii-prod");
    expect(apiMock.searchGraph).toHaveBeenCalledWith("customer-pii-prod", expect.objectContaining({ limit: 5 }));
  });

  it("keeps an unresolved resource honest: no graph link, findings search only", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [makeCheck({ check_id: "3.7", title: "Storage private", status: "fail", resource_ids: ["stpiiprod"] })],
      count: 1, source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);
    const list = await screen.findByRole("list", { name: "Resources failing 3.7" });
    await waitFor(() => expect(within(list).getByText("Not in the current graph")).toBeInTheDocument());
    expect(within(list).queryByRole("link", { name: /in the graph/ })).toBeNull();
    expect(within(list).getByRole("link", { name: "Findings on stpiiprod" })).toBeInTheDocument();
  });

  it("labels a check with no recorded result as not evaluated, never as a pass", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [makeCheck({ check_id: "4.1", title: "No open SSH", status: "not_evaluated", evidence: "No passing result recorded." })],
      count: 1, source: "scan_jobs+graph",
    });
    render(<CISBenchmarkDetail />);
    const card = (await screen.findByText("No open SSH")).closest("[data-testid='cis-check']") as HTMLElement;
    expect(within(card).getAllByTestId("cis-check-status").map((badge) => badge.textContent)).toEqual(["Not evaluated"]);
    expect(screen.getByRole("button", { name: "Not evaluated" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Pass" }));
    expect(screen.queryByText("No open SSH")).toBeNull();
  });

  it("links graph-backed resources by node id and opens their exact finding", async () => {
    const resources = Array.from({ length: 12 }, (_, index) => `snowflake:table:t${index}`);
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({
          cloud: "snowflake",
          check_id: "3.1",
          title: "Tri-Secret Secure enabled",
          status: "fail",
          resource_ids: resources,
          evidence_source: "graph",
          graph_node_id: "misconfig:snowflake_cis_benchmark:3.1",
          resource_finding_ids: { "snowflake:table:t0": ["finding-0"] },
        }),
      ],
      count: 1, source: "scan_jobs+graph",
    });
    render(<CISBenchmarkDetail />);
    const list = await screen.findByRole("list", { name: "Resources failing 3.1" });
    expect(within(list).getByRole("link", { name: "Open snowflake:table:t0 in the graph" })).toHaveAttribute(
      "href",
      "/security-graph?lens=lineage&investigate=1&root=snowflake%3Atable%3At0&node=snowflake%3Atable%3At0",
    );
    expect(within(list).getByRole("link", { name: "Findings on snowflake:table:t0" })).toHaveAttribute("href", "/findings?finding=finding-0");
    expect(within(list).getByRole("link", { name: "Findings on snowflake:table:t1" })).toHaveAttribute("href", "/findings?q=snowflake%3Atable%3At1");
    expect(apiMock.searchGraph).not.toHaveBeenCalled();
    expect(screen.queryByText("Not in the current graph")).toBeNull();
    expect(screen.getByRole("link", { name: "Open control 3.1 in the graph" })).toHaveAttribute(
      "href",
      "/security-graph?lens=lineage&investigate=1&root=misconfig%3Asnowflake_cis_benchmark%3A3.1&node=misconfig%3Asnowflake_cis_benchmark%3A3.1",
    );
    // A long resource list is bounded, with the rest one click away.
    expect(within(list).getAllByRole("listitem")).toHaveLength(10);
    fireEvent.click(screen.getByRole("button", { name: "Show all 12 resources" }));
    expect(within(list).getAllByRole("listitem")).toHaveLength(12);
  });
});
