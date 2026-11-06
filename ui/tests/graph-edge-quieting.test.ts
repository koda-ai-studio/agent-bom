import { describe, expect, it } from "vitest";
import type { Edge } from "@xyflow/react";
import { quietContextEdges } from "@/lib/graph-edge-quieting";

const edge = (id: string, source: string, target: string, data: Record<string, unknown> = {}, hidden = false): Edge => ({ id, source, target, data, hidden });
const quiet = { quietUntilFocus: true };
const edges = [edge("near", "a", "b"), edge("far", "a", "z", quiet), edge("far2", "y", "z", quiet), edge("collapsed", "a", "c", {}, true), edge("group", "a", "group", { displayOnly: true })];
const none = { showAll: false, focusNodes: [null], focusEdge: null };

describe("quietContextEdges", () => {
  it("holds back only marked edges and accounts for every recorded one", () => {
    const result = quietContextEdges(edges, none);
    expect(result.edges.filter(item => !item.hidden).map(item => item.id)).toEqual(["near", "group"]);
    expect({ drawn: result.drawn, held: result.held, total: result.total }).toEqual({ drawn: 1, held: 2, total: 4 });
  });
  it("reveals a focused node's connections at either end", () => {
    const result = quietContextEdges(edges, { ...none, focusNodes: ["z", null] });
    expect(result.edges.filter(item => !item.hidden).map(item => item.id)).toEqual(["near", "far", "far2", "group"]);
    expect(result.held).toBe(0);
  });
  it("keeps the inspected relationship drawn", () => {
    expect(quietContextEdges(edges, { ...none, focusEdge: "far" }).edges.find(item => item.id === "far")?.hidden).toBeFalsy();
  });
  it("draws everything on request and never un-hides a collapsed edge", () => {
    const result = quietContextEdges(edges, { ...none, showAll: true });
    expect(result.held).toBe(0);
    expect(result.edges.find(item => item.id === "collapsed")?.hidden).toBe(true);
  });
  it("does not touch the input", () => {
    quietContextEdges(edges, none);
    expect(edges[1]?.hidden).toBeFalsy();
  });
});
