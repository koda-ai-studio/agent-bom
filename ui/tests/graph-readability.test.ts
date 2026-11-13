import { expect, it } from "vitest";
import { MarkerType } from "@xyflow/react";
import { readableGraphEdges } from "@/lib/graph-utils";

it("keeps arrowheads readable at overview zoom without changing recorded direction", () => {
  const [edge] = readableGraphEdges([{ id: "affects", source: "finding", target: "asset", markerEnd: { type: MarkerType.ArrowClosed }, data: { quietLabel: true } }], null, { zoom: 0.5 });
  expect(edge?.source).toBe("finding");
  expect(edge?.target).toBe("asset");
  expect(edge?.markerEnd).toMatchObject({ width: 48, markerUnits: "userSpaceOnUse" });
  expect(edge?.markerStart).toBeUndefined();
});
it("preserves both ends of a recorded bidirectional link", () => {
  const marker = { type: MarkerType.ArrowClosed };
  const [edge] = readableGraphEdges([{ id: "shared", source: "a", target: "b", markerStart: marker, markerEnd: marker }]);
  expect(edge?.markerStart).toEqual(edge?.markerEnd);
});

it("reveals direction for the investigated neighborhood and preserves path emphasis", () => {
  const links = [{ id: "ab", source: "a", target: "b" }, { id: "bc", source: "b", target: "c" }];
  const result = readableGraphEdges(links, new Set(["a", "b"]));
  expect(result[0]?.data?.directionEmphasis).toBe(true);
  expect(result[1]?.data?.directionEmphasis).toBe(false);
  expect(readableGraphEdges([{ ...links[0]!, data: { directionEmphasis: true } }], undefined, { preserveVisualStyle: true })[0]?.data?.directionEmphasis).toBe(true);
});
it("keeps a high-degree parent quiet without losing relationships or direction metadata", () => {
  const edges = Array.from({ length: 90 }, (_, i) => ({ id: `edge-${i}`, source: "parent", target: `child-${i}`, markerEnd: { type: MarkerType.ArrowClosed }, data: { quietLabel: true, relationship: "contains" } }));
  const result = readableGraphEdges(edges, new Set(["parent", ...edges.map(e => e.target)]));
  expect(result).toHaveLength(90);
  expect(result.every(e => !e.label && !e.data?.directionEmphasis)).toBe(true);
  expect(result.every(e => e.markerEnd && e.source === "parent")).toBe(true);
});
it("keeps names and metadata at 12px or more when the whole default graph is fitted", async () => {
  const { readableGraphNodeStyle } = await import("@/lib/graph-node-dimensions");
  for (const zoom of [0.4, 0.45, 0.6, 1]) {
    const style = readableGraphNodeStyle(zoom) as Record<string, string>;
    expect(Number.parseFloat(style["--graph-node-label-size"]!) * zoom).toBeGreaterThanOrEqual(12);
    expect(Number.parseFloat(style["--graph-node-meta-size"]!) * zoom).toBeGreaterThanOrEqual(12);
  }
});

it("keeps evidence metadata legible at the bounded repository overview zoom", async () => {
  const { readableGraphNodeStyle } = await import("@/lib/graph-node-dimensions");
  const style = readableGraphNodeStyle(0.49) as Record<string, string>;
  expect(Number.parseFloat(style["--graph-node-meta-size"]!) * 0.49).toBeGreaterThanOrEqual(11);
});

it("draws compact cards at one on-screen size whatever zoom a small graph is fitted at", async () => {
  const { readableGraphNodeStyle } = await import("@/lib/graph-node-dimensions");
  for (const zoom of [0.5, 0.55, 0.6, 0.8, 1, 1.25, 1.6, 2.5]) {
    const style = readableGraphNodeStyle(zoom) as Record<string, string>;
    const drawn = (key: string) => Number.parseFloat(style[key]!) * zoom;
    expect(drawn("--graph-node-glyph-size")).toBeGreaterThanOrEqual(48);
    expect(drawn("--graph-node-glyph-size")).toBeLessThanOrEqual(56);
    expect(drawn("--graph-node-label-size")).toBeGreaterThanOrEqual(13);
    expect(drawn("--graph-node-label-size")).toBeLessThanOrEqual(15);
    expect(drawn("--graph-node-meta-size")).toBeGreaterThanOrEqual(12);
    expect(drawn("--graph-node-meta-size")).toBeLessThanOrEqual(13);
  }
});

it("gives a small graph a larger glyph that meets the readability floor, never the oversized circles of before", async () => {
  const { readableGraphNodeStyle, SMALL_GRAPH_NODES } = await import("@/lib/graph-node-dimensions");
  for (const count of [2, 5, SMALL_GRAPH_NODES]) for (const zoom of [0.6, 1, 1.25]) {
    const style = readableGraphNodeStyle(zoom, false, false, count) as Record<string, string>;
    const glyph = Number.parseFloat(style["--graph-node-glyph-size"]!) * zoom;
    expect(glyph).toBeGreaterThanOrEqual(65);
    expect(glyph).toBeLessThanOrEqual(72);
  }
  const large = readableGraphNodeStyle(1, false, false, SMALL_GRAPH_NODES + 1) as Record<string, string>;
  expect(Number.parseFloat(large["--graph-node-glyph-size"]!)).toBeLessThanOrEqual(56);
});
