import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AttackPathGraph } from "@/components/attack-path-graph";
import { branchingFixture, fanOutFixture } from "./fixtures/attack-path-graph-fixture";

vi.mock("@/lib/graph-node-aggregates", () => ({
  useGraphNodeAggregates: (_scan: string, hops: string[]) => new Map(hops.includes("pkg:next") ? [["pkg:next", {
    node_id: "pkg:next", semantic_layer: "package", aggregate: { issue_count: 7, worst_severity: "critical", exposed_count: 0 },
  }]] : []),
}));

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  // React Flow reads the zoom pane matrix; jsdom has none.
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});
afterEach(cleanup);

function renderGraph(fixture = branchingFixture(), props: Partial<React.ComponentProps<typeof AttackPathGraph>> = {}) {
  const onOpenFindings = vi.fn();
  const onNodeSelect = vi.fn();
  const onEdgeSelect = vi.fn();
  const view = render(<AttackPathGraph graph={fixture.graph} attackPath={fixture.selected} narrow={false}
    onOpenFindings={onOpenFindings} onNodeSelect={onNodeSelect} onEdgeSelect={onEdgeSelect} {...props} />);
  return { ...view, onOpenFindings, onNodeSelect, onEdgeSelect };
}

describe("AttackPathGraph", () => {
  it("shows the backend finding total independently of the loaded findings", () => {
    const { onOpenFindings } = renderGraph();
    const badge = screen.getByRole("button", { name: "Findings (7) on next@15.2.2, worst critical. Open loaded findings" });
    // Severity is written out, not carried by colour alone.
    expect(badge).toHaveTextContent("Findings (7)");
    expect(badge).toHaveAttribute("data-severity", "critical");
    fireEvent.click(badge);
    expect(onOpenFindings).toHaveBeenCalledWith("pkg:next", ["cve:next-2"]);
    expect(screen.queryByRole("button", { name: /Findings.*on urllib3/ })).toBeNull();
    // Explicit terminal findings remain selected-path hops.
    expect(screen.getByTestId("attack-path-node-cve:next")).toHaveAttribute("data-role", "target");
  });

  it("never draws an Internet node; exposure is a marker on the recorded node", () => {
    renderGraph();
    expect(screen.queryByText(/^internet$/i)).toBeNull();
    const exposed = screen.getByTestId("attack-path-node-server:github");
    expect(within(exposed).getByLabelText("Internet-exposed (recorded)")).toBeInTheDocument();
    expect(within(screen.getByTestId("attack-path-node-server:filesystem")).queryByLabelText(/internet/i)).toBeNull();
    expect(within(screen.getByTestId("attack-path-node-role:admin")).queryByLabelText("Privileged: admin (recorded)")).toBeNull();
  });

  it("names every hop of the selected path on its line, and a branch's relationship on hover or focus", () => {
    const { container } = renderGraph();
    for (const hop of ["Acted As", "Assumes", "Can Access", "Depends On"]) expect(screen.getAllByText(hop).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Accessed")).toHaveLength(1);
    const edge = container.querySelector('[data-id="server:filesystem->dataset:finance:accessed"]')!;
    expect(edge).not.toBeNull();
    expect(edge.getAttribute("aria-label")).toMatch(/filesystem MCP accessed finance-board-index/i);
    fireEvent.mouseEnter(edge);
    expect(screen.getAllByText("Accessed")).toHaveLength(2);
    fireEvent.mouseLeave(edge);
    expect(screen.getAllByText("Accessed")).toHaveLength(1);
    fireEvent.focus(edge);
    expect(screen.getAllByText("Accessed")).toHaveLength(2);
  });

  it("wraps a long name only at its separators and keeps the full name for assistive tech", () => {
    const fixture = branchingFixture();
    fixture.graph.nodes = fixture.graph.nodes.map(item => item.id === "pkg:urllib3" ? { ...item, label: "GCS_SERVICE_ACCOUNT_KEY" } : item);
    renderGraph(fixture);
    const name = within(screen.getByTestId("attack-path-node-pkg:urllib3")).getByTitle("GCS_SERVICE_ACCOUNT_KEY");
    expect(name.querySelectorAll("wbr")).toHaveLength(3);
    expect(name).toHaveTextContent("GCS_SERVICE_ACCOUNT_KEY");
  });

  it("draws inferred edges dashed, recorded solid, and explains both in a legend", () => {
    const { container } = renderGraph();
    const stroke = (id: string) => container.querySelector(`[data-id="${id}"] path.react-flow__edge-path`)!.getAttribute("data-line-style");
    expect(stroke("user:contractor->sa:jit:acted_as")).toBe("solid");
    expect(stroke("role:admin->agent:copilot:can_access")).toBe("dashed");
    expect(stroke("server:github->pkg:next:depends_on")).toBe("dotted");
    const legend = screen.getByRole("list", { name: "Graph legend" });
    expect(within(legend).getByText("Recorded")).toBeInTheDocument();
    expect(within(legend).getByText("Modeled or inferred")).toBeInTheDocument();
    expect(within(legend).getByText("No per-edge receipt")).toBeInTheDocument();
    expect(within(legend).getByText("Connected path")).toBeInTheDocument();
  });

  it("omits legend rows for styles and markers the graph does not use", () => {
    const fixture = fanOutFixture(0);
    renderGraph(fixture);
    const legend = screen.getByRole("list", { name: "Graph legend" });
    expect(within(legend).queryByText("Modeled or inferred")).toBeNull();
    expect(within(legend).queryByText("Connected path")).toBeNull();
    expect(within(legend).queryByText(/internet/i)).toBeNull();
  });

  it("expands a collapsed sibling group in place", () => {
    renderGraph(fanOutFixture(5));
    const expand = screen.getByRole("button", { name: "Expand 5 cloud resources" });
    fireEvent.click(expand);
    expect(screen.getByTestId("attack-path-node-endpoint:4")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Expand 5 cloud resources" })).toBeNull();
  });

  it("opens the node detail when a node is activated", () => {
    const { onNodeSelect } = renderGraph();
    fireEvent.click(within(screen.getByTestId("attack-path-node-pkg:next")).getByText("next@15.2.2"));
    expect(onNodeSelect).toHaveBeenCalledWith("pkg:next");
  });
});
