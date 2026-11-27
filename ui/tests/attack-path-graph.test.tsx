import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AttackPathGraph } from "@/components/attack-path-graph";
import { FindingBadge } from "@/components/attack-path-graph-node";
import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { AttackPathArrowDefs } from "@/components/attack-path-graph-edge";
import { branchingFixture, fanOutFixture } from "./fixtures/attack-path-graph-fixture";

vi.mock("@/lib/graph-node-aggregates", () => ({
  useGraphNodeAggregates: (_scan: string, hops: string[]) => new Map(hops.includes("pkg:next") ? [["pkg:next", {
    node_id: "pkg:next", semantic_layer: "package", aggregate: { issue_count: 7, worst_severity: "critical", severity_counts: {critical: 7}, exposed_count: 0 },
  }], ["agent:copilot", {node_id: "agent:copilot", semantic_layer: "orchestration", aggregate: {issue_count: 1, worst_severity: "critical", severity_counts: {medium: 1}}}]] : []),
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
  it("does not count a finding on itself or repeat issues already drawn as findings", () => {
    const fixture = branchingFixture();
    const model = buildAttackPathGraphModel(fixture.graph, fixture.selected);
    const asset = model.nodes.find(node => node.id === "pkg:next")!;
    const aggregate: NonNullable<typeof asset.aggregate> = { issue_count: 1, severity_counts: { critical: 1 },
      by_type: {}, descendant_count: 1, exposed_count: 0, finding_occurrence_count: 1, internet_exposed: false,
      toxic_combo: false, toxic_count: 0, worst_severity: "critical", worst_severity_rank: 5 };
    const { container, rerender } = render(<FindingBadge node={{...asset, aggregate: {...aggregate, issue_count: 0}}} onOpen={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<FindingBadge node={{...asset, aggregate, findingDisclosure: {issue_count: 0, severity_counts: {}, exclude_node_ids: ["cve:next"]}}} onOpen={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<FindingBadge node={{...model.nodes.find(node => node.id === "cve:next")!, aggregate}} onOpen={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<FindingBadge node={{...asset, aggregate: {...aggregate, issue_count: 7}, findingDisclosure: {issue_count: 6, severity_counts: {critical: 6}, exclude_node_ids: ["cve:next"]}}} onOpen={vi.fn()} />);
    expect(screen.getByLabelText(/6 additional findings.*7 in scope.*critical/)).toHaveTextContent("6");
  });
  it("keeps direction markers independent of highlighted line thickness", () => {
    const { container } = render(<AttackPathArrowDefs prefix="sizing" />);
    const markers = container.querySelectorAll("marker");
    expect(markers).toHaveLength(4);
    for (const marker of markers) {
      expect(marker).toHaveAttribute("markerUnits", "userSpaceOnUse");
      expect(Number(marker.getAttribute("markerWidth"))).toBeLessThanOrEqual(7);
    }
  });
  it("colours a scope badge by its finding severity rather than asset risk", () => {
    renderGraph();
    const badge = screen.getByLabelText("Findings (1) on Developer Copilot, worst medium");
    expect(badge).toHaveAttribute("data-severity", "medium");
  });

  it("shows the backend finding total independently of the loaded findings", () => {
    const { onOpenFindings } = renderGraph();
    const badge = screen.getByRole("button", { name: "Findings (7) on next@15.2.2, worst critical. Open loaded findings" });
    // Severity is written out, not carried by colour alone.
    expect(badge).toHaveTextContent("7");
    expect(badge).toHaveAttribute("data-severity", "critical");
    fireEvent.click(badge);
    expect(onOpenFindings).toHaveBeenCalledWith("pkg:next", ["cve:next-2"]);
    expect(screen.queryByRole("button", { name: /Findings.*on urllib3/ })).toBeNull();
    // Explicit terminal findings remain selected-path hops.
    expect(screen.getByTestId("attack-path-node-cve:next")).toHaveAttribute("data-role", "target");
  });

  it("does not promote intermediate exposure to the entry or infer privilege from legacy flags", () => {
    const fixture = branchingFixture();
    fixture.graph.nodes.find(node => node.id === "role:admin")!.attributes = { is_admin: true };
    renderGraph(fixture);
    expect(screen.queryByText(/^internet$/i)).toBeNull();
    const exposed = screen.getByTestId("attack-path-node-server:github");
    expect(within(exposed).getByLabelText("Internet-exposed (recorded)")).toBeInTheDocument();
    expect(within(screen.getByTestId("attack-path-node-server:filesystem")).queryByLabelText(/internet/i)).toBeNull();
    expect(within(screen.getByTestId("attack-path-node-role:admin")).queryByLabelText("Privileged: admin (recorded)")).toBeNull();
  });

  it("keeps ordinary path labels quiet until hover or focus and retains the privilege label", () => {
    const { container } = renderGraph();
    expect(container.querySelectorAll("[data-path-hop-label]")).toHaveLength(1);
    expect(container.querySelector("[data-path-hop-label]")).toHaveTextContent("Can Access");
    expect(screen.queryByText("Accessed")).toBeNull();
    const edge = container.querySelector('[data-id="server:filesystem->dataset:finance:accessed"]')!;
    expect(edge).not.toBeNull();
    expect(edge.getAttribute("aria-label")).toMatch(/filesystem MCP accessed finance-board-index/i);
    fireEvent.mouseEnter(edge);
    expect(screen.getAllByText("Accessed")).toHaveLength(1);
    fireEvent.mouseLeave(edge);
    expect(screen.queryByText("Accessed")).toBeNull();
    fireEvent.focus(edge);
    expect(screen.getAllByText("Accessed")).toHaveLength(1);
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
    expect(within(legend).getByText("Related asset")).toBeInTheDocument();
  });

  it("omits legend rows for styles and markers the graph does not use", () => {
    const fixture = fanOutFixture(0);
    renderGraph(fixture);
    const legend = screen.getByRole("list", { name: "Graph legend" });
    expect(within(legend).queryByText("Modeled or inferred")).toBeNull();
    expect(within(legend).queryByText("Related asset")).toBeNull();
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
