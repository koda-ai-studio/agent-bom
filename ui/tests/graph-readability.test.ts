import { expect, it } from "vitest";
import { MarkerType } from "@xyflow/react";
import { readableGraphEdges } from "@/lib/graph-utils";

it("keeps arrowheads readable at overview zoom without changing recorded direction", () => {
  const [edge] = readableGraphEdges([{ id: "affects", source: "finding", target: "asset", markerEnd: { type: MarkerType.ArrowClosed }, data: { quietLabel: true } }], null, { zoom: 0.5 });
  expect(edge?.source).toBe("finding");
  expect(edge?.target).toBe("asset");
  expect(edge?.markerEnd).toMatchObject({ width: 72, markerUnits: "userSpaceOnUse" });
  expect(edge?.markerStart).toBeUndefined();
});
it("preserves both ends of a recorded bidirectional link", () => {
  const marker = { type: MarkerType.ArrowClosed };
  const [edge] = readableGraphEdges([{ id: "shared", source: "a", target: "b", markerStart: marker, markerEnd: marker }]);
  expect(edge?.markerStart).toEqual(edge?.markerEnd);
});
