import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ComplianceControlDrawer } from "@/components/compliance-control-drawer";
import { controlTagFor, pathSupportReason } from "@/lib/control-evidence";
import type { ComplianceControl } from "@/lib/api";

const listFindings = vi.fn();
const getGraphAttackPaths = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      listFindings: (...args: unknown[]) => listFindings(...args),
      getGraphAttackPaths: (...args: unknown[]) => getGraphAttackPaths(...args),
    },
  };
});

const control: ComplianceControl = {
  code: "GOVERN-6.1", name: "Policies address AI risks from third-party entities", findings: 556, status: "fail",
  severity_breakdown: { critical: 103, high: 449, medium: 4 }, affected_packages: [], affected_agents: ["claude-desktop", "data-pipeline"],
};

function finding(i: number) {
  return {
    id: `f-${i}`, finding_id: `f-${i}`, severity: i === 0 ? "critical" : "high", title: `CVE-2023-48${i}: pillow@9.0.0`,
    cve_id: `CVE-2023-48${i}`, node_id: i === 1 ? "pkg:pypi:pillow@9.0.0:image:0108bac4395b" : "pkg:pypi:pillow@9.0.0", finding_node_id: `vuln:CVE-2023-48${i}`, entity_type: "server",
    asset: { name: i === 0 ? "etl-server" : `bucket-${i}`, asset_type: i === 0 ? "mcp_server" : "s3_bucket" },
    affected_agents: ["data-pipeline"], package: "pillow@9.0.0", scan_id: "showcase",
    framework_tags: ["cis:CIS-02.3", "nist_ai_rmf:GOVERN-6.1"],
  };
}

const path = {
  source: "agent:data-pipeline", target: "vuln:CVE-2023-4863", hops: ["agent:data-pipeline", "server:etl-server", "pkg:pypi:pillow@9.0.0", "vuln:CVE-2023-4863"],
  edges: [], composite_risk: 90.6, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: ["CVE-2023-4863"],
  finding_ids: ["f-0"], reachability: "likely", severity: "high",
};

beforeEach(() => {
  listFindings.mockResolvedValue({ findings: Array.from({ length: 10 }, (_, i) => finding(i)), total: 556, count: 10, has_more: true });
  getGraphAttackPaths.mockResolvedValue({
    attack_paths: [path], pagination: { total: 646, offset: 0, limit: 5, has_more: true },
    nodes: [{ id: "agent:data-pipeline", label: "Data Pipeline" }, { id: "vuln:CVE-2023-4863", label: "CVE-2023-4863" }],
  });
});
afterEach(() => { listFindings.mockReset(); getGraphAttackPaths.mockReset(); });

function open() {
  return render(<ComplianceControlDrawer control={control} frameworkId="nist-ai-rmf" frameworkLabel="NIST AI RMF 1.0" scanId="showcase" onClose={() => {}} />);
}

describe("control evidence helpers", () => {
  it("reads the control tag the finding actually carries", () => {
    expect(controlTagFor(["cis:CIS-02.3", "nist_ai_rmf:GOVERN-6.1"], "GOVERN-6.1")).toBe("nist_ai_rmf:GOVERN-6.1");
    expect(controlTagFor(["nist_ai_rmf:GOVERN-6.10"], "GOVERN-6.1")).toBeNull();
    expect(controlTagFor(undefined, "GOVERN-6.1")).toBeNull();
  });

  it("explains a path by the finding it ends on and that finding's control tag", () => {
    expect(pathSupportReason(path, "GOVERN-6.1", "nist_ai_rmf:GOVERN-6.1")).toBe("Ends on CVE-2023-4863, which carries nist_ai_rmf:GOVERN-6.1");
    expect(pathSupportReason({ ...path, vuln_ids: [] }, "GOVERN-6.1", null)).toBe("Ends on finding f-0, which is mapped to GOVERN-6.1");
  });
});

describe("control drawer evidence", () => {
  it("opens on the evidence: the control's own count, basis and supporting paths", async () => {
    open();
    expect(screen.getByRole("tab", { name: "Evidence" })).toHaveAttribute("aria-selected", "true");
    const summary = await screen.findByTestId("control-evidence-summary");
    expect(summary).toHaveTextContent("Counted by control-tag evidence: 556 findings carry");
    expect(summary).toHaveTextContent("Ranked by effective reach");
    await waitFor(() => expect(summary).toHaveTextContent("646 attack paths support this control"));
    expect(getGraphAttackPaths).toHaveBeenCalledWith(expect.objectContaining({ framework: "nist-ai-rmf", control: "GOVERN-6.1", scanId: "showcase" }));
  });

  it("lists mapped findings with severity, asset kind and links into the graph and findings", async () => {
    open();
    const list = await screen.findByRole("list", { name: "Findings mapped to GOVERN-6.1" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(10);
    const first = rows[0]!;
    expect(first).toHaveTextContent(/critical/i);
    expect(first).toHaveTextContent("etl-server");
    expect(within(first).getByTestId("asset-kind")).toHaveAttribute("title", expect.stringMatching(/MCP server/i));
    const graph = within(first).getByRole("link", { name: "Open etl-server in the graph" });
    const params = new URL(graph.getAttribute("href")!, "http://x").searchParams;
    expect(params.get("lens")).toBe("attack-path");
    expect(params.get("finding")).toBe("f-0");
    expect(params.get("node")).toBe("pkg:pypi:pillow@9.0.0");
    expect(rows[1]).toHaveTextContent("in image 0108bac4395b");
    expect(within(first).getByRole("link", { name: "Open finding CVE-2023-480" })).toHaveAttribute(
      "href", "/findings?finding=f-0&framework=nist-ai-rmf&control=GOVERN-6.1",
    );
    expect(listFindings).toHaveBeenCalledWith(expect.objectContaining({ framework: "nist-ai-rmf", control: "GOVERN-6.1", limit: 10, offset: 0 }));
  });

  it("pages the finding list on the server", async () => {
    open();
    await screen.findByRole("list", { name: "Findings mapped to GOVERN-6.1" });
    expect(screen.getByText(/Page 1 of 56/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Next/ }));
    await waitFor(() => expect(listFindings).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 10 })));
  });

  it("shows why each path supports the control and opens it in the graph", async () => {
    open();
    await screen.findByRole("list", { name: "Findings mapped to GOVERN-6.1" });
    fireEvent.click(screen.getByRole("button", { name: /Attack paths/ }));
    const list = await screen.findByRole("list", { name: "Attack paths supporting GOVERN-6.1" });
    const row = within(list).getAllByRole("listitem")[0]!;
    expect(row).toHaveTextContent("Data Pipeline");
    expect(row).toHaveTextContent("Ends on CVE-2023-4863, which carries nist_ai_rmf:GOVERN-6.1");
    const link = within(row).getByRole("link", { name: /Open path/ });
    const params = new URL(link.getAttribute("href")!, "http://x").searchParams;
    expect(params.get("framework")).toBe("nist-ai-rmf");
    expect(params.get("control")).toBe("GOVERN-6.1");
    expect(params.get("finding")).toBe("f-0");
    expect(params.get("selected_path")).toBe(`${path.source}::${path.target}::${path.hops.join("->")}`);
  });

  it("says plainly when the API returns no mapped findings", async () => {
    listFindings.mockResolvedValue({ findings: [], total: 0, count: 0, has_more: false });
    getGraphAttackPaths.mockResolvedValue({ attack_paths: [], pagination: { total: 0, offset: 0, limit: 5, has_more: false }, nodes: [] });
    open();
    expect(await screen.findByText(/No current findings carry this control's tag/)).toBeInTheDocument();
  });
});
