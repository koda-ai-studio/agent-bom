import type { Edge, Node } from "@xyflow/react";
import { describe, expect, it } from "vitest";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { allEdgesModeled, edgeFamily, edgeIsDashed } from "@/lib/graph-edge-family";
import { flowEdgeLegend } from "@/lib/graph-flow-legend";
import { INTERNET_ANCHOR_ID } from "@/lib/graph-internet-context";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";

const node = (id: string, nodeType: string, attributes: Record<string, unknown> = {}, extra: Partial<LineageNodeData> = {}): Node<LineageNodeData> =>
  ({ id, type: "x", position: { x: 0, y: 0 }, data: { label: id, nodeType, attributes, ...extra } as LineageNodeData });
const edge = (id: string, source: string, target: string, relationship: string, data: Record<string, unknown> = {}): Edge =>
  ({ id, source, target, data: { relationship, evidenceMode: "inferred", ...data } });
const dashed = (e: Edge) => edgeIsDashed(edgeFamily(String(e.data?.relationship)), e.data);

describe("a view whose every link is modeled", () => {
  const nodes = [node("w", "container", { internet_exposed: true }), node("p", "package"), node("env", "environment")];
  const edges = [edge("e1", "w", "p", "contains"), edge("e2", "env", "w", "hosts")];

  it("draws every link solid, the Internet anchor link included", () => {
    const out = semanticGraphLayout(nodes, edges);
    expect(out.edges.some(e => e.source === INTERNET_ANCHOR_ID)).toBe(true);
    expect(out.edges.filter(dashed)).toEqual([]);
  });

  it("reaches the same answer when the layout runs again over its own output", () => {
    const once = semanticGraphLayout(nodes, edges);
    const twice = semanticGraphLayout(once.nodes, once.edges);
    expect(twice.edges.filter(dashed).map(e => e.id)).toEqual([]);
    expect(twice.edges.every(e => e.data?.uniformlyModeled === true)).toBe(true);
  });

  it("tells the legend the links are modeled, never recorded", () => {
    const legend = flowEdgeLegend(semanticGraphLayout(nodes, edges).edges);
    expect(legend.styles).toContain("modeled");
    expect(legend.styles).not.toContain("solid");
  });
});

describe("dashes still distinguish when they carry meaning", () => {
  it("keeps modeled links dashed beside recorded ones", () => {
    const edges = [edge("a", "x", "y", "contains"), edge("b", "y", "z", "contains", { evidenceMode: "recorded" })];
    expect(allEdgesModeled(edges)).toBe(false);
    const out = semanticGraphLayout([node("x", "agent"), node("y", "server"), node("z", "package")], edges);
    expect(out.edges.find(e => e.id === "a") && dashed(out.edges.find(e => e.id === "a")!)).toBe(true);
    expect(dashed(out.edges.find(e => e.id === "b")!)).toBe(false);
  });

  it("never draws a blocked link solid", () => {
    const blocked = { relationship: "contains", evidenceMode: "inferred", evidenceBlocked: true, uniformlyModeled: true };
    expect(edgeIsDashed("structure", blocked)).toBe(true);
    expect(allEdgesModeled([{ data: blocked }, { data: { relationship: "contains", evidenceMode: "inferred" } }])).toBe(false);
  });
});

describe("the Internet anchor and cross-row links", () => {
  it("marks the anchored node so its exposure dot is not drawn twice", () => {
    const out = semanticGraphLayout([node("w", "container", { internet_exposed: true }), node("p", "package")], [edge("e1", "w", "p", "contains")]);
    expect(out.nodes.find(n => n.id === "w")?.data.internetAnchored).toBe(true);
    expect(out.nodes.find(n => n.id === "p")?.data.internetAnchored).toBeUndefined();
  });

  it("gives the Internet arrow its own entry when another link enters the same node", () => {
    const nodes = [node("w", "container", { internet_exposed: true }), node("p", "package"), node("env", "environment")];
    const out = semanticGraphLayout(nodes, [edge("path", "w", "p", "contains"), edge("env-w", "env", "w", "hosts")]);
    expect(out.edges.find(e => e.source === INTERNET_ANCHOR_ID)!.targetHandle).toBe("above");
    expect(out.edges.find(e => e.id === "env-w")!.targetHandle).toBeNull();
    const alone = semanticGraphLayout([node("w", "container", { internet_exposed: true }), node("p", "package")], [edge("path", "w", "p", "contains")]);
    expect(alone.edges.find(e => e.source === INTERNET_ANCHOR_ID)!.targetHandle).toBeNull();
  });
});
