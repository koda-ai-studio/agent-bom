import { Position } from "@xyflow/react";
import { describe, expect, it } from "vitest";
import { relationshipPath } from "@/lib/relationship-routing";

const edge = { source: "finding", target: "data", sourceX: 72, sourceY: 36, targetX: 672, targetY: 36,
  sourcePosition: Position.Right, targetPosition: Position.Left };

describe("relationship routing", () => {
  it("keeps an unobstructed relationship on its direct curve", () => {
    expect(relationshipPath(edge, [])[2]).toBe(36);
  });
  it("routes a long relationship and its label above an intervening entity", () => {
    const route = relationshipPath(edge, [{ id: "endpoint", x: 260, y: 0, width: 220, height: 180 }]);
    expect(route[2]).toBeLessThan(-16);
    expect(route[0]).toMatch(/^M72,36/);
    expect(route[0]).toMatch(/672,36$/);
  });
  it("keeps a diagonal relationship label clear of an intermediate entity", () => {
    const route = relationshipPath({ ...edge, sourceY: 170 }, [{ id: "intermediate", x: 260, y: 0, width: 220, height: 180 }]);
    expect(route[2]).toBeGreaterThan(196);
  });
  it("does not detour a diagonal whose bounding box contains a distant card", () => {
    const diagonal = { ...edge, sourceY: 300, targetY: 0 };
    const obstacles = [{ id: "other", x: 400, y: 240, width: 100, height: 80 }];
    expect(relationshipPath(diagonal, obstacles)).toEqual(relationshipPath(diagonal, []));
  });
  it("preserves vertical and reverse-direction curves", () => {
    const obstacles = [{ id: "endpoint", x: 260, y: 0, width: 220, height: 180 }];
    const vertical = { ...edge, sourcePosition: Position.Bottom, targetPosition: Position.Top };
    expect(relationshipPath(vertical, obstacles)).toEqual(relationshipPath(vertical, []));
    const reverse = { ...edge, sourceX: 672, targetX: 72, sourcePosition: Position.Left, targetPosition: Position.Right };
    expect(relationshipPath(reverse, obstacles)).toEqual(relationshipPath(reverse, []));
  });
  it("places a serpentine row turn outside the wider node label column", () => {
    const turn = { ...edge, targetX: 72, targetY: 256, targetPosition: Position.Right };
    const route = relationshipPath(turn, [{ id: "finding", x: 0, y: 0, width: 220, height: 180 }]);
    expect(route[1]).toBeGreaterThan(240);
    expect(route[2]).toBe(146);
  });
  it("separates captions for shared-source routes branching above and below", () => {
    const obstacles = [{ id: "middle", x: 260, y: 0, width: 220, height: 180 }];
    const above = relationshipPath({ ...edge, sourceY: 100, targetY: 36 }, obstacles);
    const below = relationshipPath({ ...edge, sourceY: 100, targetY: 164 }, obstacles);
    expect(Math.abs(above[1] - below[1])).toBeGreaterThan(100);
  });
  it("keeps a shifted caption out of its endpoint bounds", () => {
    const diagonal = { ...edge, sourceY: 300, targetY: 0 };
    const shifted = relationshipPath(diagonal, []);
    const sourceBounds = { id: "finding", x: shifted[1] - 40, y: shifted[2] - 20, width: 80, height: 40 };
    const safe = relationshipPath(diagonal, [sourceBounds]);
    expect(safe[0]).toBe(shifted[0]);
    expect(Math.abs(safe[1] - shifted[1])).toBeGreaterThan(48);
  });
  it("excludes the relationship endpoints from obstacles", () => {
    expect(relationshipPath(edge, [{ id: "finding", x: 0, y: 0, width: 220, height: 180 }])[2]).toBe(36);
  });
});
