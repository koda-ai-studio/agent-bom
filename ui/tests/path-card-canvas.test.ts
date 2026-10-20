import type { Edge } from "@xyflow/react";
import { describe, expect, it } from "vitest";

import {
  PATH_CARD_CANVAS_CLASS,
  PATH_CARD_CANVAS_MAX_PX,
  PATH_CARD_CANVAS_MIN_PX,
  pathCardCanvasHeight,
  pathCardEdges,
} from "@/lib/path-card-canvas";

const at = (x: number, y: number) => ({ position: { x, y } });

describe("pathCardCanvasHeight", () => {
  it("gives a single-row path a short canvas instead of the full investigation height", () => {
    const height = pathCardCanvasHeight([at(0, 0), at(336, 0), at(672, 2), at(1008, 0)]);
    expect(height).toBeGreaterThanOrEqual(PATH_CARD_CANVAS_MIN_PX);
    expect(height).toBeLessThan(340);
  });

  it("grows with each row and stays bounded", () => {
    const one = pathCardCanvasHeight([at(0, 0), at(336, 0)]);
    const two = pathCardCanvasHeight([at(0, 0), at(336, 260)]);
    expect(two).toBeGreaterThan(one);
    const many = pathCardCanvasHeight(Array.from({ length: 12 }, (_, index) => at(0, index * 260)));
    expect(many).toBe(PATH_CARD_CANVAS_MAX_PX);
  });

  it("falls back to the minimum when nothing is laid out", () => {
    expect(pathCardCanvasHeight([])).toBe(PATH_CARD_CANVAS_MIN_PX);
  });
});

describe("pathCardEdges", () => {
  const edges: Edge[] = [
    { id: "uses", source: "a", target: "b", data: { relationship: "uses" }, style: { strokeWidth: 1.5, strokeDasharray: "6 3", opacity: 0.5 } },
    { id: "depends", source: "b", target: "c", data: { relationship: "depends_on" }, style: { strokeWidth: 1.5, opacity: 1 } },
  ];

  it("keeps strokes and dashes a constant, legible screen size at any zoom", () => {
    const [dashed, solid] = pathCardEdges(edges, 0.5);
    expect(dashed!.style?.strokeWidth).toBe(4);
    expect(dashed!.style?.strokeDasharray).toBe("12 8");
    expect(dashed!.style?.opacity).toBeGreaterThanOrEqual(0.9);
    expect(solid!.style?.strokeDasharray).toBeUndefined();
    expect(pathCardEdges(edges, 1)[0]!.style?.strokeWidth).toBe(2);
  });
});

describe("PATH_CARD_CANVAS_CLASS", () => {
  it("lets only a card's visible content take pointer input", () => {
    expect(PATH_CARD_CANVAS_CLASS).toContain("[&_[aria-roledescription=node]]:pointer-events-none!");
    expect(PATH_CARD_CANVAS_CLASS).toContain("[&_[data-graph-entity]>*]:pointer-events-auto!");
  });

  it("never relies on literal underscores, which Tailwind turns into spaces", () => {
    for (const variant of PATH_CARD_CANVAS_CLASS.split(" ")) expect(variant.replace(/^\[&_/, "")).not.toMatch(/__/);
  });
});
