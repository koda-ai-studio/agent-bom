import { describe, expect, it } from "vitest";

import {
  PATH_SERPENTINE_STEP,
  applySerpentinePath,
  planSerpentinePath,
  serpentinePositions,
} from "@/lib/path-serpentine-layout";

const MIN_READABLE_ZOOM = 12 / 18;

describe("planSerpentinePath", () => {
  it("wraps a 7-node path into rows at a desktop investigation width with readable labels", () => {
    const plan = planSerpentinePath(7, { containerWidth: 808, maxCanvasHeight: 600 });
    expect(plan.columns).toBeLessThan(7);
    expect(plan.rows).toBeGreaterThan(1);
    expect(plan.zoom).toBeGreaterThanOrEqual(MIN_READABLE_ZOOM);
    expect(plan.canvasHeight).toBeLessThanOrEqual(600);
  });

  it("sizes the canvas to the wrapped path instead of leaving empty rows", () => {
    const plan = planSerpentinePath(7, { containerWidth: 1000, maxCanvasHeight: 600 });
    const contentHeight = plan.height * plan.zoom;
    expect(plan.canvasHeight - contentHeight).toBeLessThan(120);
  });

  it("keeps a single row when the whole path fits at full size", () => {
    expect(planSerpentinePath(3, { containerWidth: 1600, maxCanvasHeight: 600 }).rows).toBe(1);
  });

  it("stacks into one column on narrow mobile canvases", () => {
    const plan = planSerpentinePath(7, { containerWidth: 358, maxCanvasHeight: 600 });
    expect(plan.columns).toBe(1);
  });

  it("handles empty and invalid input without NaN", () => {
    const plan = planSerpentinePath(0, { containerWidth: Number.NaN, maxCanvasHeight: 600 });
    expect(Number.isFinite(plan.zoom)).toBe(true);
    expect(plan.columns).toBe(1);
  });
});

describe("serpentinePositions", () => {
  it("alternates row direction so each turn stays on one side", () => {
    const positions = serpentinePositions(["a", "b", "c", "d", "e"], 2, PATH_SERPENTINE_STEP);
    const at = (id: string) => positions.get(id)!;
    expect([at("a").reverse, at("c").reverse, at("e").reverse]).toEqual([false, true, false]);
    expect(at("b").x).toBe(at("c").x);
    expect(at("d").x).toBe(at("e").x);
    expect(at("a").x).toBeLessThan(at("b").x);
    expect(at("c").y).toBeGreaterThan(at("b").y);
  });
});

describe("applySerpentinePath", () => {
  const node = (id: string) => ({ id, position: { x: 0, y: 0 }, data: { label: id } as { label: string; reverseFlow?: boolean } });

  it("only reflows when every node on the canvas is an ordered path hop", () => {
    const nodes = ["a", "b", "x"].map(node);
    expect(applySerpentinePath(nodes, ["a", "b"], 2)).toBe(nodes);
  });

  it("positions hops in path order and marks reversed rows", () => {
    const nodes = ["c", "a", "b"].map(node);
    const result = applySerpentinePath(nodes, ["a", "b", "c"], 2);
    const byId = new Map(result.map((item) => [item.id, item]));
    expect(byId.get("c")!.data.reverseFlow).toBe(true);
    expect(byId.get("a")!.data.reverseFlow).toBe(false);
    expect(byId.get("c")!.position.y).toBeGreaterThan(byId.get("a")!.position.y);
  });
});
