import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AttackPathGraph } from "@/components/attack-path-graph";
import { branchingFixture, fanOutFixture } from "./fixtures/attack-path-graph-fixture";

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
  it("shows a finding badge whose count equals the findings recorded on the asset", () => {
    const { onOpenFindings } = renderGraph();
    const badge = screen.getByRole("button", { name: "2 findings on next@15.2.2, worst critical. Open findings" });
    expect(badge).toHaveTextContent("2");
    expect(badge).toHaveAttribute("data-severity", "critical");
    fireEvent.click(badge);
    expect(onOpenFindings).toHaveBeenCalledWith("pkg:next", ["cve:next", "cve:next-2"]);
    expect(screen.getByRole("button", { name: "1 finding on urllib3@2.2.1, worst high. Open findings" })).toHaveTextContent("1");
    // The vulnerability is never a node of the chain.
    expect(screen.queryByTestId("attack-path-node-cve:next")).toBeNull();
  });

  it("never draws an Internet node; exposure is a marker on the recorded node", () => {
    renderGraph();
    expect(screen.queryByText(/^internet$/i)).toBeNull();
    const exposed = screen.getByTestId("attack-path-node-server:github");
    expect(within(exposed).getByLabelText("Internet-exposed (recorded)")).toBeInTheDocument();
    expect(within(screen.getByTestId("attack-path-node-server:filesystem")).queryByLabelText(/internet/i)).toBeNull();
    expect(within(screen.getByTestId("attack-path-node-role:admin")).getByLabelText("Privileged: admin (recorded)")).toBeInTheDocument();
  });

  it("hides relationship labels until an edge is hovered or focused", () => {
    const { container } = renderGraph();
    expect(screen.queryByText("Acted As")).toBeNull();
    const edge = container.querySelector('[data-id="user:contractor->sa:jit:acted_as"]')!;
    expect(edge).not.toBeNull();
    expect(edge.getAttribute("aria-label")).toMatch(/contractor-reviewer acted as jit-prod-reviewer/i);
    fireEvent.mouseEnter(edge);
    expect(screen.getByText("Acted As")).toBeInTheDocument();
    fireEvent.mouseLeave(edge);
    expect(screen.queryByText("Acted As")).toBeNull();
    fireEvent.focus(edge);
    expect(screen.getByText("Acted As")).toBeInTheDocument();
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
