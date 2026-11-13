import { describe, expect, it } from "vitest";
import type { Edge } from "@xyflow/react";
import { flowEdgeLegend } from "@/lib/graph-flow-legend";

const edge = (id: string, relationship: string, stroke: string, extra: Partial<Edge> = {}, dash?: string): Edge => ({
  id, source: `${id}-s`, target: `${id}-t`, data: { relationship, relationshipLabel: relationship.replace("_", " ") },
  style: { stroke, ...(dash ? { strokeDasharray: dash } : {}) }, ...extra,
});

describe("flowEdgeLegend", () => {
  it("explains only the line styles and relationship colours the canvas draws", () => {
    const legend = flowEdgeLegend([
      edge("a", "uses", "var(--edge-uses)"),
      edge("b", "uses", "var(--edge-uses)"),
      edge("c", "exposes_cred", "var(--edge-cred)", {}, "6 3"),
      edge("hidden", "contains", "var(--edge-contains)", { hidden: true }),
    ]);
    expect(legend.styles).toEqual(["solid", "dashed"]);
    expect(legend.relationships).toEqual([
      { relationship: "uses", label: "uses", stroke: "var(--edge-uses)", count: 2 },
      { relationship: "exposes_cred", label: "exposes cred", stroke: "var(--edge-cred)", count: 1 },
    ]);
    expect(legend.more).toBe(0);
  });

  it("names runtime motion and caps the colour list with a remainder", () => {
    const edges = Array.from({ length: 9 }, (_, index) => edge(`e${index}`, `rel_${index}`, `var(--c${index})`, index === 0 ? { animated: true } : {}));
    const legend = flowEdgeLegend(edges);
    expect(legend.styles).toEqual(["solid", "runtime"]);
    expect(legend.relationships).toHaveLength(6);
    expect(legend.more).toBe(3);
  });

  it("lists no colours when every line is drawn in the same colour", () => {
    const legend = flowEdgeLegend([edge("a", "uses", "var(--line)"), edge("b", "depends_on", "var(--line)")]);
    expect(legend.relationships).toEqual([]);
    expect(legend.more).toBe(0);
  });

  it("is empty for a canvas without drawn relationships", () => {
    expect(flowEdgeLegend([])).toEqual({ styles: [], relationships: [], more: 0 });
  });
});
