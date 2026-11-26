import { fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { GraphScopeOverview } from "@/components/graph-scope-overview";
import type { GraphRollupContainer } from "@/lib/api-types";

vi.mock("@xyflow/react", () => ({
  MarkerType: { ArrowClosed: "arrowclosed" },
  ReactFlow: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  ReactFlowProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
  Background: () => null,
}));
vi.mock("@/components/lineage-nodes", () => ({ lineageNodeTypes: {} }));
vi.mock("@/components/relationship-edge", () => ({ relationshipEdgeTypes: {} }));
vi.mock("@/components/graph-legible-controls", () => ({ LegibleFitControls: () => null }));
vi.mock("@/hooks/use-narrow-viewport", () => ({ useNarrowViewport: () => false }));

const root: GraphRollupContainer = {
  id: "org:recorded", label: "Recorded organization", entity_type: "org", severity: "none",
  is_container: true, has_children: true, direct_child_count: 40,
  aggregate: { descendant_count: 5578, by_type: {}, severity_counts: { critical: 336, high: 790 },
    issue_count: 1923, worst_severity: "critical", worst_severity_rank: 5,
    internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 },
};
const children = ["a", "b", "c"].map(id => ({ ...root, id, label: id, entity_type: "source_file", has_children: false, is_container: false }));
const edges = children.map(child => ({ source: root.id, target: child.id, count: 2, relationships: ["affects"], directions: ["directed"] }));

describe("scope preview navigation", () => {
  it("keeps recorded scope totals visible and drills into containment without opening a neighborhood", () => {
    const drill = vi.fn(), investigate = vi.fn();
    render(<GraphScopeOverview items={[root, ...children]} edges={edges} onDrill={drill} onInvestigate={investigate} />);
    expect(screen.getByTestId("graph-preview-scope-counts")).toHaveTextContent("5,578 contained nodes · 40 direct children · 1,923 open issues");
    fireEvent.click(screen.getByRole("button", { name: "Open scope" }));
    expect(drill).toHaveBeenCalledWith(root);
    expect(investigate).not.toHaveBeenCalled();
  });

  it("does not manufacture an issue count when an older response has no issue total", () => {
    const unknown = { ...root, aggregate: { ...root.aggregate, issue_count: undefined } };
    render(<GraphScopeOverview items={[unknown, ...children]} edges={edges} onDrill={vi.fn()} onInvestigate={vi.fn()} />);
    expect(screen.getByTestId("graph-preview-scope-counts")).not.toHaveTextContent("open issues");
  });
});
