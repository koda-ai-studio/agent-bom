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

  it("names runtime motion and every drawn relationship colour", () => {
    const edges = Array.from({ length: 9 }, (_, index) => edge(`e${index}`, `rel_${index}`, `var(--c${index})`, index === 0 ? { animated: true } : {}));
    const legend = flowEdgeLegend(edges);
    expect(legend.styles).toEqual(["solid", "runtime"]);
    expect(legend.relationships).toHaveLength(9);
    expect(legend.more).toBe(0);
  });

  it("names every relationship drawn in one colour on that colour's entry", () => {
    const legend = flowEdgeLegend([edge("a", "uses", "var(--line)"), edge("b", "depends_on", "var(--line)"), edge("c", "uses", "var(--line)")]);
    expect(legend.relationships).toEqual([{ relationship: "depends_on", label: "uses, depends on", stroke: "var(--line)", count: 3 }]);
    expect(legend.more).toBe(0);
  });

  it("reports a compact link's family colour and dash, which is what the canvas draws, not its stored style", () => {
    const compact = (id: string, relationship: string, data: Record<string, unknown> = {}): Edge => ({
      id, source: `${id}-s`, target: `${id}-t`, type: "compact", style: { stroke: "var(--edge-per-relationship)" },
      data: { relationship, relationshipLabel: `${relationship.replace("_", " ")} · modeled`, ...data },
    });
    const legend = flowEdgeLegend([compact("a", "acted_as"), compact("b", "authenticates_as"), compact("c", "depends_on", { evidenceMode: "recorded" })]);
    expect(legend.styles).toEqual(["solid", "dashed"]);
    expect(legend.relationships).toEqual([
      { relationship: "acted_as", label: "acted as, authenticates as", stroke: "var(--graph-edge-access)", count: 2 },
      { relationship: "depends_on", label: "depends on", stroke: "var(--graph-edge-structure)", count: 1 },
    ]);
  });

  it("is empty for a canvas without drawn relationships", () => {
    expect(flowEdgeLegend([])).toEqual({ styles: [], relationships: [], more: 0 });
  });
});
