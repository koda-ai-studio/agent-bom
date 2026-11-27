import { describe, expect, it } from "vitest";

import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { attackPathCanvasHeight, attackPathCanvasWidth, NARROW_MIN_ZOOM, PATH_DESKTOP_MIN_ZOOM, layoutAttackPathGraph } from "@/lib/attack-path-graph-layout";
import { ATTACK_PATH_FIT_PADDING, FINDING_BADGE_OVERHANG, attackPathViewport } from "@/lib/attack-path-graph-viewport";
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

  it("keeps a findings badge on the rightmost node inside the pane", () => {
    const { graph, selected } = demoFixture("headline");
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    // The badge is a 22px count circle anchored 8px past the 56px glyph's right edge, inside the card.
    const glyphRight = layout.nodeWidth / 2 + 28;
    expect(FINDING_BADGE_OVERHANG).toBeGreaterThanOrEqual(glyphRight + 8 - layout.nodeWidth);
    for (const width of [1100, 1400]) {
      const pane = { width, height: 600 };
      const viewport = attackPathViewport(layout, model.pathNodeIds, pane, 0.6);
      const right = Math.max(...screenBoxes(layout, viewport).map(box => box.right));
      expect(right + FINDING_BADGE_OVERHANG * viewport.zoom).toBeLessThanOrEqual(pane.width - 8);
    }
  });

  it("fits a six-hop path on a 1280px laptop at the readable floor", () => {
    const { graph, selected } = demoFixture("headline");
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    // 1280px viewport minus the 240px navigation and page gutters leaves a 940px canvas.
    const pane = { width: 940, height: 332 };
    const viewport = attackPathViewport(layout, model.pathNodeIds, pane, PATH_DESKTOP_MIN_ZOOM);
    expect(viewport.zoom).toBeGreaterThanOrEqual(PATH_DESKTOP_MIN_ZOOM);
    const boxes = screenBoxes(layout, viewport).filter(box => model.pathNodeIds.includes(box.id));
    for (const box of boxes) {
      expect(box.left, box.id).toBeGreaterThanOrEqual(0);
      expect(box.right, box.id).toBeLessThanOrEqual(pane.width);
    }
  });

  it("keeps the phone path vertical without a sideways canvas at readable zoom", () => {
    const { graph, selected } = demoFixture("headline");
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "TB");
    expect(layout.direction).toBe("TB");
    expect(new Set(model.pathNodeIds.map(id => layout.positions.get(id)!.x)).size).toBe(1);
    for (const frameWidth of [342, 520]) {
      const width = attackPathCanvasWidth(layout, true, frameWidth);
      const pane = { width, height: attackPathCanvasHeight(layout, true, width) };
      const viewport = attackPathViewport(layout, model.pathNodeIds, pane, NARROW_MIN_ZOOM);
      expect(width).toBe(frameWidth);
      expect(viewport.zoom).toBeGreaterThanOrEqual(NARROW_MIN_ZOOM);
      expect(viewport.hiddenNodeIds).toEqual([]);
      for (const box of screenBoxes(layout, viewport)) {
        expect(box.left).toBeGreaterThanOrEqual(0);
        expect(box.right).toBeLessThanOrEqual(pane.width);
        expect(box.top).toBeGreaterThanOrEqual(0);
        expect(box.bottom).toBeLessThanOrEqual(pane.height);
      }
    }
  });

  it("keeps the selected path whole and names what is off screen when the graph would fall below the floor", () => {
    const { graph, selected } = demoFixture("runbook");
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const pane = { width: 760, height: 460 }; // the runbook branch is two rows tall: shorter than this pane fits it whole
    const viewport = attackPathViewport(layout, model.pathNodeIds, pane, 0.6);
    expect(viewport.zoom).toBeGreaterThanOrEqual(0.6);
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

it("reserves badge room before framing phone context to the left of the selected spine", () => {
  const layout = {
    direction: "LR" as const, nodeWidth: 152, nodeHeight: 136, width: 1152, height: 840,
    positions: new Map([["left-context", { x: 0, y: 0 }], ["spine", { x: 600, y: 336 }], ["right-context", { x: 1000, y: 0 }]]),
  };
  const width = attackPathCanvasWidth(layout, true, 358);
  const height = attackPathCanvasHeight(layout, true, width);
  const viewport = attackPathViewport(layout, ["spine"], { width, height }, NARROW_MIN_ZOOM);
  expect(viewport.hiddenNodeIds).toEqual([]);
  expect(viewport.zoom).toBeGreaterThanOrEqual(NARROW_MIN_ZOOM);
  const right = viewport.x + layout.width * viewport.zoom;
  expect(right + FINDING_BADGE_OVERHANG * viewport.zoom).toBeLessThanOrEqual(width);
});

it("fits phone branches inside the nested 306px investigation panel without shrinking glyphs", () => {
  const { graph, selected } = fanOutFixture(3);
  const model = buildAttackPathGraphModel(graph, selected, { collapseThreshold: 100 });
  const layout = layoutAttackPathGraph(model, "TB");
  const width = 306, height = attackPathCanvasHeight(layout, true, width);
  const viewport = attackPathViewport(layout, model.pathNodeIds, { width, height }, NARROW_MIN_ZOOM);
  expect(viewport.hiddenNodeIds).toEqual([]);
  expect(viewport.zoom * 56).toBeGreaterThanOrEqual(48);
  const boxes = screenBoxes(layout, viewport);
  for (const a of boxes) for (const b of boxes) if (a.id !== b.id) {
    expect(a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top).toBe(true);
  }
});
