import { describe, expect, it } from "vitest";

import {
  COLUMN_MAX_NODES,
  COLUMN_STEP,
  applyColumnPath,
  columnCanvasHeight,
  columnEdgePath,
  columnFlowEdges,
  usesColumnPath,
} from "@/lib/path-card-column";

const node = (id: string, x = 0, y = 0) => ({ id, position: { x, y }, data: { label: id, reverseFlow: true } });

describe("usesColumnPath", () => {
  it("stacks a short focused path on a narrow viewport", () => {
    expect(usesColumnPath({ narrow: true, focusMode: true, nodeCount: 4 })).toBe(true);
    expect(usesColumnPath({ narrow: true, focusMode: true, nodeCount: COLUMN_MAX_NODES })).toBe(true);
  });

  it("keeps the stepper for paths too long for one column", () => {
    expect(usesColumnPath({ narrow: true, focusMode: true, nodeCount: COLUMN_MAX_NODES + 1 })).toBe(false);
  });

  it("never applies on desktop or to loaded context", () => {
    expect(usesColumnPath({ narrow: false, focusMode: true, nodeCount: 4 })).toBe(false);
    expect(usesColumnPath({ narrow: true, focusMode: false, nodeCount: 4 })).toBe(false);
    expect(usesColumnPath({ narrow: true, focusMode: true, nodeCount: 0 })).toBe(false);
  });
});

describe("applyColumnPath", () => {
  it("places every hop top-to-bottom in path order with forward handles", () => {
    const placed = applyColumnPath([node("c", 600), node("a", 0), node("b", 300)], ["a", "b", "c"]);
    const byId = new Map(placed.map(item => [item.id, item]));
    expect(byId.get("a")!.position).toEqual({ x: 0, y: 0 });
    expect(byId.get("b")!.position).toEqual({ x: 0, y: COLUMN_STEP });
    expect(byId.get("c")!.position).toEqual({ x: 0, y: 2 * COLUMN_STEP });
    for (const item of placed) expect(item.data.reverseFlow).toBe(false);
  });

  it("leaves a canvas with nodes off the path unchanged", () => {
    const nodes = [node("a"), node("b"), node("context")];
    expect(applyColumnPath(nodes, ["a", "b"])).toBe(nodes);
  });
});

describe("columnCanvasHeight", () => {
  it("grows with the path and stays bounded", () => {
    expect(columnCanvasHeight(4)).toBeGreaterThan(columnCanvasHeight(2));
    expect(columnCanvasHeight(4)).toBeLessThanOrEqual(800);
    expect(columnCanvasHeight(COLUMN_MAX_NODES)).toBeLessThanOrEqual(1080);
    expect(columnCanvasHeight(0)).toBeGreaterThanOrEqual(288);
  });
});

describe("columnEdgePath", () => {
  it("draws a vertical link from under the source card to the top of the next glyph", () => {
    // Glyph centre x=150, radius 40: source handle on the right, target on the left.
    const [path, x, y] = columnEdgePath({ sourceX: 190, sourceY: 40, targetX: 110, targetY: 270 }, 180);
    expect(path).toBe("M150,180 L150,230");
    expect(x).toBe(150);
    expect(y).toBe(205);
  });
});

describe("columnFlowEdges", () => {
  it("stacks only links between consecutive hops", () => {
    const edges = [
      { id: "ab", source: "a", target: "b", data: {} },
      { id: "ac", source: "a", target: "c", data: {} },
      { id: "bc", source: "b", target: "c" },
    ];
    const marked = columnFlowEdges(edges, ["a", "b", "c"]);
    expect(marked.map(edge => (edge.data as { columnFlow?: boolean } | undefined)?.columnFlow === true)).toEqual([true, false, true]);
  });
});
