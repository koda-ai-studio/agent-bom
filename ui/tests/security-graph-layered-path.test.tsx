import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { branchingFixture } from "./fixtures/attack-path-graph-fixture";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: null, loading: false }) }));
vi.mock("@/components/graph-entity-drawer", () => ({
  GraphEntityDrawer: ({ data }: { data: { label: string } }) => <output data-testid="drawer">{data.label}</output>,
}));
vi.mock("@/components/graph-relationship-detail", () => ({
  GraphRelationshipDetail: ({ edge }: { edge: { relationship: string } }) => <output data-testid="relationship">{edge.relationship}</output>,
}));
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";

vi.mock("@/lib/graph-node-aggregates", () => ({
  useGraphNodeAggregates: (_scan: string, hops: string[]) => new Map([
    { node_id: "pkg:next", semantic_layer: "package", aggregate: { issue_count: 7, worst_severity: "critical", exposed_count: 0 } },
    { node_id: "pkg:urllib3", semantic_layer: "package", aggregate: { issue_count: 1, worst_severity: "high", exposed_count: 0 } },
  ].filter(row => hops.includes(row.node_id)).map(row => [row.node_id, row])),
}));

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});
afterEach(cleanup);

function renderLayered(extraFinding = false) {
  const { graph, selected } = branchingFixture();
  if (extraFinding) {
    graph.nodes.push({ ...graph.nodes.find(node => node.id === "cve:next-2")!, id: "cve:extra", label: "CVE-2025-00002" });
    graph.edges.push({ ...graph.edges.find(edge => edge.target === "cve:next-2")!, id: "extra", target: "cve:extra" });
  }
  return render(<SecurityGraphInvestigation embedded graph={graph} attackPath={selected} focusMode onFocusModeChange={vi.fn()}
    fullGraphHref="/graph" scanId="scan-1" />);
}

describe("embedded focused path", () => {
  it("renders the complete backend path including its terminal CVE hop", () => {
    renderLayered();
    const canvas = screen.getByTestId("security-graph-investigation");
    expect(canvas).toHaveAttribute("data-path-layout", "layered");
    expect(within(canvas).getByTestId("attack-path-node-cve:next")).toHaveAttribute("data-role", "target");
    expect(within(canvas).getByTestId("attack-path-node-pkg:next")).toHaveAttribute("data-role", "path");
    expect(within(canvas).getAllByText("Depends On").length).toBeGreaterThan(0);
    expect(screen.getByRole("toolbar", { name: "Graph controls" })).toBeInTheDocument();
  });

  it("opens a single finding's detail straight from its badge", async () => {
    renderLayered();
    fireEvent.click(screen.getByRole("button", { name: /^Findings \(7\) on next@15\.2\.2/ }));
    await waitFor(() => expect(screen.getByTestId("drawer")).toHaveTextContent("CVE-2025-00001"));
  });

  it("lists several loaded findings independently of the backend total, then opens the chosen one", async () => {
    renderLayered(true);
    fireEvent.click(screen.getByRole("button", { name: /^Findings \(7\) on next@15\.2\.2/ }));
    const list = screen.getByRole("region", { name: "Findings on next@15.2.2" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    fireEvent.click(within(list).getByText("CVE-2025-00001"));
    await waitFor(() => expect(screen.getByTestId("drawer")).toHaveTextContent("CVE-2025-00001"));
  });

  it("opens a branch node's detail", async () => {
    renderLayered();
    fireEvent.click(within(screen.getByTestId("attack-path-node-dataset:finance")).getByText("finance-board-index"));
    await waitFor(() => expect(screen.getByTestId("drawer")).toHaveTextContent("finance-board-index"));
  });

  it("opens the relationship detail from the keyboard", async () => {
    const { container } = renderLayered();
    const line = container.querySelector('[data-id="user:contractor->sa:jit:acted_as"]')!;
    fireEvent.keyDown(line, { key: "Enter" });
    await waitFor(() => expect(screen.getByTestId("relationship")).toHaveTextContent("acted_as"));
  });

  it("opens a node's detail from the keyboard", async () => {
    const { container } = renderLayered();
    fireEvent.keyDown(container.querySelector('.react-flow__node[data-id="role:admin"]')!, { key: "Enter" });
    await waitFor(() => expect(screen.getByTestId("drawer")).toHaveTextContent("prod-ai-admin"));
  });

  it("opens the relationship detail for a recorded edge", async () => {
    const { container } = renderLayered();
    fireEvent.click(container.querySelector('[data-id="agent:copilot->server:filesystem:uses"]')!);
    await waitFor(() => expect(screen.getByTestId("relationship")).toHaveTextContent("uses"));
  });
});
