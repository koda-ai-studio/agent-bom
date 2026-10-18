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
