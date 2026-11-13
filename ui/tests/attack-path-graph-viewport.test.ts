import { describe, expect, it } from "vitest";

import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { layoutAttackPathGraph } from "@/lib/attack-path-graph-layout";
import { ATTACK_PATH_FIT_PADDING, attackPathViewport } from "@/lib/attack-path-graph-viewport";
import { demoFixture, fanOutFixture } from "./fixtures/attack-path-graph-fixture";

function screenBoxes(layout: ReturnType<typeof layoutAttackPathGraph>, viewport: { x: number; y: number; zoom: number }) {
  return [...layout.positions].map(([id, position]) => ({
    id,
    left: viewport.x + position.x * viewport.zoom, right: viewport.x + (position.x + layout.nodeWidth) * viewport.zoom,
    top: viewport.y + position.y * viewport.zoom, bottom: viewport.y + (position.y + layout.nodeHeight) * viewport.zoom,
  }));
}

describe("attack path viewport", () => {
  it("fits every node inside the padded pane when the fitted zoom stays readable", () => {
    const { graph, selected } = demoFixture("headline");
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const pane = { width: 1400, height: 600 };
    const viewport = attackPathViewport(layout, model.pathNodeIds, pane, 0.6);
    expect(viewport.zoom).toBeGreaterThanOrEqual(0.6);
    expect(viewport.hiddenNodeIds).toEqual([]);
    for (const box of screenBoxes(layout, viewport)) {
      expect(box.left).toBeGreaterThanOrEqual(ATTACK_PATH_FIT_PADDING.left - 0.5);
      expect(box.right).toBeLessThanOrEqual(pane.width - ATTACK_PATH_FIT_PADDING.right + 0.5);
      expect(box.top).toBeGreaterThanOrEqual(ATTACK_PATH_FIT_PADDING.top - 0.5);
      // The zoom controls sit in the bottom-left corner; nodes stay above them.
      expect(box.bottom).toBeLessThanOrEqual(pane.height - ATTACK_PATH_FIT_PADDING.bottom + 0.5);
    }
  });

  it("moves a phone's path column toward the centre as far as keeping every branch visible allows", () => {
    const { graph, selected } = demoFixture("headline");
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "TB");
    const pad = ATTACK_PATH_FIT_PADDING;
    const middle = (width: number) => pad.left + (width - pad.left - pad.right) / 2;
    for (const width of [342, 520]) {
      const pane = { width, height: 2200 };
      const viewport = attackPathViewport(layout, model.pathNodeIds, pane, 0.7);
      expect(viewport.hiddenNodeIds).toEqual([]);
      const spine = screenBoxes(layout, viewport).find(box => box.id === model.pathNodeIds[0])!;
      const offset = (spine.left + spine.right) / 2 - middle(width);
      const left = viewport.x, right = viewport.x + layout.width * viewport.zoom;
      expect(left).toBeGreaterThanOrEqual(pad.left - 0.5);
      expect(right).toBeLessThanOrEqual(width - pad.right + 0.5);
      // Centred, or held off centre only because the branch side already touches its padded edge.
      if (Math.abs(offset) >= 1) expect(offset > 0 ? Math.abs(left - pad.left) : Math.abs(right - (width - pad.right))).toBeLessThan(1);
    }
    // With room to spare the column is exactly centred.
    const wide = attackPathViewport(layout, model.pathNodeIds, { width: 900, height: 2200 }, 0.7);
    const spine = screenBoxes(layout, wide).find(box => box.id === model.pathNodeIds[0])!;
    expect(Math.abs((spine.left + spine.right) / 2 - middle(900))).toBeLessThan(1);
  });

  it("keeps the selected path whole and names what is off screen when the graph would fall below the floor", () => {
    const { graph, selected } = demoFixture("runbook");
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const pane = { width: 760, height: 520 };
    const viewport = attackPathViewport(layout, model.pathNodeIds, pane, 0.6);
    expect(viewport.zoom).toBe(0.6);
    expect(viewport.fallback).toBe(true);
    const boxes = screenBoxes(layout, viewport);
    for (const id of model.pathNodeIds) {
      const box = boxes.find(item => item.id === id)!;
      expect(box.left).toBeGreaterThanOrEqual(0);
      expect(box.right).toBeLessThanOrEqual(pane.width);
    }
    const offscreen = boxes.filter(box => box.left < 0 || box.right > pane.width || box.top < 0 || box.bottom > pane.height).map(box => box.id).sort();
    expect(viewport.hiddenNodeIds.slice().sort()).toEqual(offscreen);
    expect(offscreen.length).toBeGreaterThan(0);
  });

  it("opens a graph too tall for the pane with the selected path at the top, at a readable zoom", () => {
    const { graph, selected } = fanOutFixture(6);
    const model = buildAttackPathGraphModel(graph, selected, { collapseThreshold: 100 });
    const layout = layoutAttackPathGraph(model, "LR");
    const pane = { width: 1100, height: 520 };
    const viewport = attackPathViewport(layout, model.pathNodeIds, pane, 0.6);
    expect(viewport.zoom).toBeGreaterThanOrEqual(0.6);
    const boxes = screenBoxes(layout, viewport);
    for (const id of model.pathNodeIds) {
      const box = boxes.find(item => item.id === id)!;
      expect(box.top, id).toBeGreaterThanOrEqual(ATTACK_PATH_FIT_PADDING.top - 0.5);
      expect(box.top, id).toBeLessThanOrEqual(ATTACK_PATH_FIT_PADDING.top + 0.5);
      expect(box.left, id).toBeGreaterThanOrEqual(0);
      expect(box.right, id).toBeLessThanOrEqual(pane.width);
    }
    expect(viewport.hiddenNodeIds.length).toBeGreaterThan(0);
    for (const id of viewport.hiddenNodeIds) expect(model.pathNodeIds).not.toContain(id);
  });
});
