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
