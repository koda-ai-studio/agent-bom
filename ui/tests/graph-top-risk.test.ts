import { describe, expect, it } from "vitest";
import type { Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { rankTopRisks } from "@/lib/graph-top-risk";
import { buildLargeGraphOverviewModel, LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES } from "@/lib/large-graph-overview";

const node = (id: string, data: Partial<LineageNodeData>): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType: "package", ...data } as LineageNodeData });

describe("rankTopRisks", () => {
  it("orders by recorded score, then severity, then known exploitation", () => {
    const ranked = rankTopRisks([
      node("high", { severity: "high", riskScore: 9.5 }), node("critical", { severity: "critical", riskScore: 8 }),
      node("kev", { severity: "critical", riskScore: 8, isKev: true }), node("unscored", { severity: "low" }),
    ]);
    expect(ranked.map(risk => risk.id)).toEqual(["high", "kev", "critical", "unscored"]);
  });
  it("never ranks an asset with no recorded risk, so a clean estate lists nothing", () => {
    expect(rankTopRisks([node("a", {}), node("b", { severity: "none", riskScore: 0 })])).toEqual([]);
  });
  it("folds repeats of one finding into a counted line", () => {
    const ranked = rankTopRisks(Array.from({ length: 9 }, (_, index) => node(`n${index}`, { label: "Same finding", severity: "critical", riskScore: 8 })));
    expect(ranked).toHaveLength(1);
    expect(ranked[0]).toMatchObject({ id: "n0", count: 9 });
  });
  it("ignores an unrecognised severity rather than rendering it", () => {
    expect(rankTopRisks([node("a", { severity: "x);background:url(y)", riskScore: 3 })])[0]?.severity).toBeUndefined();
  });
  it("skips display-only nodes, which are not assets", () => {
    expect(rankTopRisks([node("a", { displayOnly: true, severity: "critical", riskScore: 9 })])).toEqual([]);
  });
});

describe("the overview draw budget", () => {
  it("keeps the named risks on the map at thousands of nodes, without blocking a frame's worth of work for long", () => {
    const nodes = Array.from({ length: 20_000 }, (_, index) => node(`agent-${index}`, { nodeType: "agent" }));
    nodes.push(node("buried", { nodeType: "package", severity: "critical", riskScore: 9.9 }));
    const started = performance.now();
    const model = buildLargeGraphOverviewModel(nodes, []);
    const elapsed = performance.now() - started;
    expect(model.nodes).toHaveLength(LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES);
    expect(model.nodes.some(item => item.id === "buried")).toBe(true);
    expect(model.topRisks[0]?.id).toBe("buried");
    expect(elapsed).toBeLessThan(500);
    console.info(`overview model for 20,001 nodes: ${elapsed.toFixed(1)}ms`);
  });
});
