import { describe, expect, it } from "vitest";

import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import {
  ATTACK_PATH_CANVAS_BOUNDS,
  attackPathCanvasHeight,
  narrowFitZoom,
  layoutAttackPathGraph,
} from "@/lib/attack-path-graph-layout";
import { branchingFixture, fanOutFixture } from "./fixtures/attack-path-graph-fixture";

describe("attack path graph layout", () => {
  it("lays the selected path out left to right in hop order", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const x = model.pathNodeIds.map(id => layout.positions.get(id)!.x);
    expect(x).toEqual([...x].sort((a, b) => a - b));
    expect(new Set(x).size).toBe(x.length);
  });

  it("fans branches out vertically from the shared node instead of extending the row", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const shared = layout.positions.get("agent:copilot")!;
    const branch = layout.positions.get("server:filesystem")!;
    const onPath = layout.positions.get("server:github")!;
    expect(branch.x).toBe(onPath.x);
    expect(branch.y).not.toBe(onPath.y);
    expect(branch.x).toBeGreaterThan(shared.x);
    const rects = [...layout.positions.values()];
    for (let i = 0; i < rects.length; i += 1) {
      for (let j = i + 1; j < rects.length; j += 1) {
        const a = rects[i]!, b = rects[j]!;
        const overlap = a.x < b.x + layout.nodeWidth && b.x < a.x + layout.nodeWidth && a.y < b.y + layout.nodeHeight && b.y < a.y + layout.nodeHeight;
        expect(overlap).toBe(false);
      }
    }
  });

  it("keeps the selected path on one straight row with branches in rows off it", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const spineY = new Set(model.pathNodeIds.map(id => layout.positions.get(id)!.y));
    expect(spineY.size).toBe(1);
    const row = [...spineY][0]!;
    for (const node of model.nodes.filter(item => item.role === "branch")) {
      expect(layout.positions.get(node.id)!.y).not.toBe(row);
    }
    const vertical = layoutAttackPathGraph(model, "TB");
    expect(new Set(model.pathNodeIds.map(id => vertical.positions.get(id)!.x)).size).toBe(1);
  });

  it("keeps generous column and branch-row spacing", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const x = model.pathNodeIds.map(id => layout.positions.get(id)!.x);
    for (let index = 1; index < x.length; index += 1) {
      expect(x[index]! - x[index - 1]!).toBeGreaterThanOrEqual(180);
      expect(x[index]! - x[index - 1]!).toBeLessThanOrEqual(240);
    }
    const rowGap = Math.abs(layout.positions.get("server:filesystem")!.y - layout.positions.get("server:github")!.y);
    // Branch rows sit ~176-200px apart so names never crowd the row below.
    expect(rowGap).toBeGreaterThanOrEqual(176);
    expect(rowGap).toBeLessThanOrEqual(200);
  });

  it("stacks a phone layout top to bottom", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "TB");
    const y = model.pathNodeIds.map(id => layout.positions.get(id)!.y);
    expect(y).toEqual([...y].sort((a, b) => a - b));
    expect(layout.height).toBeGreaterThan(layout.width);
  });

  it("gives a phone the whole column at a readable zoom instead of shrinking it", () => {
    const { graph, selected } = branchingFixture();
    const layout = layoutAttackPathGraph(buildAttackPathGraphModel(graph, selected), "TB");
    const zoom = narrowFitZoom(layout, 358);
    expect(zoom).toBeGreaterThanOrEqual(0.7);
    expect(zoom).toBeLessThanOrEqual(1);
    const height = attackPathCanvasHeight(layout, true, 358);
    expect(height).toBeGreaterThanOrEqual(Math.round(layout.height * zoom));
    expect(height).toBeGreaterThan(ATTACK_PATH_CANVAS_BOUNDS.max);
  });

  it("sizes the canvas to the laid-out graph within bounds", () => {
    const short = layoutAttackPathGraph(buildAttackPathGraphModel(fanOutFixture(0).graph, fanOutFixture(0).selected), "LR");
    expect(attackPathCanvasHeight(short, false)).toBeLessThanOrEqual(ATTACK_PATH_CANVAS_BOUNDS.min + 40);
    const { graph, selected } = branchingFixture();
    const branched = layoutAttackPathGraph(buildAttackPathGraphModel(graph, selected), "LR");
    // A narrower canvas fits a smaller zoom, so it reserves less height, never empty bands.
    expect(attackPathCanvasHeight(branched, false, 800)).toBeLessThan(attackPathCanvasHeight(branched, false, 1600));
    const height = attackPathCanvasHeight(branched, false);
    expect(height).toBeGreaterThan(ATTACK_PATH_CANVAS_BOUNDS.min);
    expect(height).toBeLessThanOrEqual(ATTACK_PATH_CANVAS_BOUNDS.max);
    const tall = layoutAttackPathGraph(buildAttackPathGraphModel(fanOutFixture(40).graph, fanOutFixture(40).selected, { collapseThreshold: 100 }), "LR");
    expect(attackPathCanvasHeight(tall, false)).toBe(ATTACK_PATH_CANVAS_BOUNDS.max);
  });
});
