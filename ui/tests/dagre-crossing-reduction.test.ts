import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import { applyDagreLayout, countStraightCrossings, reduceRankCrossings } from "@/lib/dagre-layout";
import { READABLE_LINEAGE_DAGRE_LR } from "@/lib/graph-node-dimensions";

const at = (id: string, x: number, y: number): Node => ({ id, position: { x, y }, data: {} });
const link = (source: string, target: string): Edge => ({ id: `${source}-${target}`, source, target });

describe("rank crossing reduction", () => {
  it("swaps siblings within a rank when that removes a crossing", () => {
    const nodes = [at("a", 0, 0), at("b", 0, 100), at("c", 300, 0), at("d", 300, 100)];
    const edges = [link("a", "d"), link("b", "c")];
    expect(countStraightCrossings(nodes, edges)).toBe(1);
    const reduced = reduceRankCrossings(nodes, edges);
    expect(countStraightCrossings(reduced, edges)).toBe(0);
    expect(new Set(reduced.map((n) => n.position.x))).toEqual(new Set([0, 300]));
  });

  it("leaves an already crossing-free layout untouched", () => {
    const nodes = [at("a", 0, 0), at("b", 0, 100), at("c", 300, 0), at("d", 300, 100)];
    const edges = [link("a", "c"), link("b", "d")];
    expect(reduceRankCrossings(nodes, edges)).toEqual(nodes);
  });

  it("untangles the reference correlation order dagre produced (source pin above the deployment)", () => {
    const nodes = [
      at("service", 0, 0), at("pinned", 0, 144), at("iac", 0, 288), at("sbom", 0, 432),
      at("workload", 207, 0), at("pillow", 207, 288), at("identity", 414, 0), at("tool", 414, 144), at("cve", 414, 288),
    ];
    const edges = [
      link("service", "workload"), link("iac", "workload"), link("iac", "pillow"), link("sbom", "pillow"),
      link("pinned", "pillow"), link("pillow", "cve"), link("workload", "identity"), link("workload", "tool"),
    ];
    expect(countStraightCrossings(nodes, edges)).toBeGreaterThan(0);
    expect(countStraightCrossings(reduceRankCrossings(nodes, edges), edges)).toBe(0);
  });

  it("applies the pass inside the dagre layout", () => {
    const ids = ["a", "b", "c", "d"];
    const laid = applyDagreLayout(ids.map((id) => at(id, 0, 0)), [link("a", "d"), link("b", "c")], { ...READABLE_LINEAGE_DAGRE_LR, direction: "LR" }).nodes;
    expect(countStraightCrossings(laid, [link("a", "d"), link("b", "c")])).toBe(0);
  });
});

describe("rank spacing for tall layouts", () => {
  it("widens the gaps between ranks of a tall left-to-right layout so captions fit, keeping rank order", () => {
    const ids = ["s1", "s2", "s3", "s4", "hub", "leaf"];
    const edges = [link("s1", "hub"), link("s2", "hub"), link("s3", "hub"), link("s4", "hub"), link("hub", "leaf")];
    const laid = applyDagreLayout(ids.map((id) => at(id, 0, 0)), edges, { ...READABLE_LINEAGE_DAGRE_LR, direction: "LR" }).nodes;
    const x = new Map(laid.map((n) => [n.id, n.position.x]));
    const ys = laid.map((n) => n.position.y);
    const width = Math.max(...x.values()) - Math.min(...x.values()) + READABLE_LINEAGE_DAGRE_LR.nodeWidth!;
    const height = Math.max(...ys) - Math.min(...ys) + READABLE_LINEAGE_DAGRE_LR.nodeHeight!;
    const plain = applyDagreLayout(ids.map((id) => at(id, 0, 0)), edges, { ...READABLE_LINEAGE_DAGRE_LR, direction: "LR", fitAspect: undefined }).nodes;
    const plainSpan = Math.max(...plain.map((n) => n.position.x)) - Math.min(...plain.map((n) => n.position.x));
    expect(width - READABLE_LINEAGE_DAGRE_LR.nodeWidth!).toBeCloseTo(plainSpan * 2, 5);
    expect(width / height).toBeGreaterThan(1.5);
    expect(x.get("s1")!).toBeLessThan(x.get("hub")!);
    expect(x.get("hub")!).toBeLessThan(x.get("leaf")!);
  });

  it("does not stretch a layout that is already wide", () => {
    const chain = ["a", "b", "c", "d"].map((id) => at(id, 0, 0));
    const edges = [link("a", "b"), link("b", "c"), link("c", "d")];
    const withFit = applyDagreLayout(chain, edges, { ...READABLE_LINEAGE_DAGRE_LR, direction: "LR" }).nodes.map((n) => n.position);
    const plain = applyDagreLayout(chain, edges, { ...READABLE_LINEAGE_DAGRE_LR, direction: "LR", fitAspect: undefined }).nodes.map((n) => n.position);
    expect(withFit).toEqual(plain);
  });
});

it("keeps top-to-bottom ranks intact (the swap pass is left-to-right only)", () => {
  const ids = ["a", "b", "c", "d", "e"];
  const edges = [link("a", "d"), link("b", "c"), link("a", "e"), link("b", "e")];
  const laid = applyDagreLayout(ids.map((id) => at(id, 0, 0)), edges, { direction: "TB", nodeWidth: 240, nodeHeight: 216, rankSep: 32, nodeSep: 24 }).nodes;
  const y = new Map(laid.map((n) => [n.id, n.position.y]));
  for (const edge of edges) expect(y.get(edge.source)!).toBeLessThan(y.get(edge.target)!);
});
