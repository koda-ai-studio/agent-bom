import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ReactFlowProvider } from "@xyflow/react";
import { GraphFindingGroupNode } from "@/components/graph-finding-group-node";
import type { LineageNodeData } from "@/components/lineage-nodes";

const data = (toggle = vi.fn(), count = 2, severity?: string): LineageNodeData => ({
  label: "Findings", nodeType: "misconfiguration", displayOnly: true, description: "pod: prod/web",
  readingFindings: { count, expanded: false, ...(severity ? { severity } : {}), toggle },
}) as unknown as LineageNodeData;
const view = (nodeData: LineageNodeData) => render(<ReactFlowProvider><GraphFindingGroupNode data={nodeData} /></ReactFlowProvider>);

describe("GraphFindingGroupNode", () => {
  it("names the group by what it belongs to and counts what it holds", () => {
    view(data());
    expect(screen.getByRole("button", { name: "Expand 2 findings for pod: prod/web" })).toBeTruthy();
    expect(screen.getByText("Click to expand · 2 loaded")).toBeTruthy();
  });

  it("uses the singular for one finding", () => {
    view(data(vi.fn(), 1));
    expect(screen.getByRole("button", { name: "Expand 1 finding for pod: prod/web" })).toBeTruthy();
  });

  it("toggles once without bubbling to the canvas click handler", () => {
    const toggle = vi.fn(), outer = vi.fn();
    render(<div onClick={outer}><ReactFlowProvider><GraphFindingGroupNode data={data(toggle)} /></ReactFlowProvider></div>);
    fireEvent.click(screen.getByRole("button"));
    expect(toggle).toHaveBeenCalledTimes(1);
    expect(outer).not.toHaveBeenCalled();
  });

  it("keeps connection handles outside the button, one for each side an edge can arrive from", () => {
    const { container } = view(data());
    expect(screen.getByRole("button").querySelector(".react-flow__handle")).toBeNull();
    const handles = [...container.querySelectorAll(".react-flow__handle")];
    expect(handles).toHaveLength(2);
    expect(handles.map(handle => handle.getAttribute("data-handlepos")).sort()).toEqual(["left", "right"]);
  });

  it("marks the group as a finding group with the card width the flow sets", () => {
    const { container } = view(data());
    const card = container.querySelector<HTMLElement>('[data-graph-entity="finding-group"]');
    expect(card?.style.width).toBe("var(--graph-node-card-width, 240px)");
  });
});
