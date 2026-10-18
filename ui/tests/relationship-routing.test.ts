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
  it("excludes the relationship endpoints from obstacles", () => {
    expect(relationshipPath(edge, [{ id: "finding", x: 0, y: 0, width: 220, height: 180 }])[2]).toBe(36);
  });
});

it("gives detour bends room to turn before reaching a clear horizontal lane", () => {
  const [path] = relationshipPath(edge, [{ id: "middle", x: 260, y: 0, width: 220, height: 180 }]);
  const points = path.match(/-?\d+(?:\.\d+)?/g)!.map(Number);
  // The first cubic arrives horizontally with a substantial easing interval,
  // instead of forcing the entire turn into the old 32-unit elbow.
  expect(points[6]! - points[2]!).toBeGreaterThanOrEqual(64);
  expect(points[6]!).toBeLessThan(260);
  expect(points[7]).toBeLessThan(0);
});

it("uses a clear sibling gap before routing outside the node envelope", () => {
  const obstacles = [{ id: "upper", x: 260, y: 0, width: 220, height: 170 }, { id: "lower", x: 260, y: 220, width: 220, height: 170 }];
  const route = relationshipPath({ ...edge, sourceY: 220 }, obstacles);
  expect(route[2]).toBeGreaterThanOrEqual(186);
  expect(route[2]).toBeLessThanOrEqual(204);
});

it("keeps a caption detour clear of an unrelated node in a skipped row", () => {
  const middle = { id: "middle", x: 132, y: 260, width: 220, height: 160 };
  const [path] = relationshipPath({ ...edge, sourceX: 150, sourceY: 40, targetX: 70, targetY: 640 }, [
    { id: "finding", x: 0, y: 0, width: 220, height: 180 }, middle,
    { id: "data", x: 0, y: 600, width: 220, height: 180 },
  ]);
  let previous = [0, 0];
  const crossings: number[][] = [];
  for (const match of path.matchAll(/([MLQC])([^MLQC]+)/g)) {
    const values = match[2]!.trim().split(/[ ,]+/).map(Number);
    const end = values.slice(-2);
    if (match[1] !== "M") for (let sample = 0; sample <= 100; sample++) {
      const t = sample / 100, u = 1 - t;
      const point = end.map((value, axis) => match[1] === "C"
        ? u ** 3 * previous[axis]! + 3 * u * u * t * values[axis]! + 3 * u * t * t * values[axis + 2]! + t ** 3 * value
        : match[1] === "Q"
        ? u * u * previous[axis]! + 2 * u * t * values[axis]! + t * t * value
        : u * previous[axis]! + t * value);
      if (point[0]! > middle.x && point[0]! < middle.x + middle.width && point[1]! > middle.y && point[1]! < middle.y + middle.height) crossings.push(point);
    }
    previous = end;
  }
  expect(crossings).toEqual([]);
  expect(path).toMatch(/^M150,40/);
  expect(path).toMatch(/70,640$/);
});
