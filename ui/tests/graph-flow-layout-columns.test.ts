import { expect, it } from "vitest";
import type { Edge } from "@xyflow/react";
import type { FlowNode } from "@/lib/graph-flow-model";
import { FLOW_COLUMN_GAP, placeFlow } from "@/lib/graph-flow-layout";

const node = (id: string): FlowNode => ({ id, type: "containerNode", position: { x: 0, y: 0 }, data: { label: id, nodeType: "container", attributes: {} } });
const edge = (source: string, target: string): Edge => ({ id: `${source}-${target}`, source, target });

function layout(pathLength: number, contextCount: number) {
  const path = Array.from({ length: pathLength }, (_, index) => `p${index}`);
  const context = Array.from({ length: contextCount }, (_, index) => `c${String(index).padStart(2, "0")}`);
  const next = new Map(path.slice(0, -1).map((id, index) => [id, [path[index + 1]!]]));
  const previous = new Map(path.slice(1).map((id, index) => [id, [path[index]!]]));
  // Every context card leads into the path's first column, so each asks for a column before it.
  const edges = [...path.slice(1).map((id, index) => edge(path[index]!, id)), ...context.map(id => edge(id, path[0]!))];
  const placed = placeFlow({ visible: [...path, ...context].map(node), ranks: new Map(path.map((id, index) => [id, index])), primary: path, steps: { next, previous }, edges, narrow: false });
  const columns = new Set([...placed.values()].map(point => point.x / FLOW_COLUMN_GAP));
  return { placed, columns, span: Math.max(...columns) - Math.min(...columns) + 1 };
}

it("does not open a column before the path when the path already fills the grid's width", () => {
  // Twenty cards make a seven-column grid; a seven-step path already uses every column.
  const { placed, span } = layout(7, 13);
  expect(span).toBe(7);
  expect(placed.get("p0")).toEqual({ x: 0, y: 0 });
});

it("opens a column before the path for a parent while the grid has width to spare, and keeps the total width", () => {
  const { placed, columns, span } = layout(2, 18);
  expect(Math.min(...columns)).toBe(-1);
  expect(span).toBeLessThanOrEqual(7);
  expect(placed.get("p0")).toEqual({ x: 0, y: 0 });
});
