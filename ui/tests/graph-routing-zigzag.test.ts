import { Position } from "@xyflow/react";
import { expect, it } from "vitest";
import { relationshipPath } from "@/lib/relationship-routing";

it("routes through alternating local gaps without returning a colliding direct curve", () => {
  const obstacles = [
    { id: "upper", x: 200, y: -500, width: 100, height: 550 },
    { id: "lower", x: 450, y: -50, width: 100, height: 550 },
  ];
  const [path] = relationshipPath({ source: "a", target: "b", sourceX: 0, sourceY: 0, targetX: 800, targetY: 0,
    sourcePosition: Position.Right, targetPosition: Position.Left }, obstacles);
  const values = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
  expect(path).not.toMatch(/[LQ]/);
  for (let index = 0; index < values.length - 2; index += 6) for (let step = 0; step <= 200; step++) {
    const t = step / 200, u = 1 - t;
    const [x, y] = [0, 1].map(axis => u ** 3 * values[index + axis]! + 3 * u ** 2 * t * values[index + axis + 2]!
      + 3 * u * t ** 2 * values[index + axis + 4]! + t ** 3 * values[index + axis + 6]!);
    expect(obstacles.some(box => x! > box.x - 12 && x! < box.x + box.width + 12 && y! > box.y - 12 && y! < box.y + box.height + 12)).toBe(false);
    expect(Math.abs(y!)).toBeLessThan(200);
  }
});

it("keeps a descending curve out of its own source caption", () => {
  const source = { id: "source", x: 0, y: 0, width: 300, height: 200 };
  const target = { id: "target", x: 420, y: 420, width: 220, height: 200 };
  const [path] = relationshipPath({ source: "source", target: "target", sourceX: 182, sourceY: 36, targetX: 494, targetY: 456,
    sourcePosition: Position.Right, targetPosition: Position.Left }, [source, target]);
  const values = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
  for (let index = 0; index < values.length - 2; index += 6) for (let step = 0; step <= 200; step++) {
    const t = step / 200, u = 1 - t;
    const [x, y] = [0, 1].map(axis => u ** 3 * values[index + axis]! + 3 * u ** 2 * t * values[index + axis + 2]!
      + 3 * u * t ** 2 * values[index + axis + 4]! + t ** 3 * values[index + axis + 6]!);
    expect(x! > 0 && x! < 300 && y! > 90 && y! < 200).toBe(false);
  }
});

it("uses the measured 24px gap between caption boxes without crossing a peer", () => {
  const boxes = [
    { id: "agent", x: 2280, y: -360, width: 240, height: 301 },
    { id: "bucket", x: 2280, y: -35, width: 240, height: 265 },
    { id: "cluster", x: 2280, y: 254, width: 240, height: 265 },
    { id: "gateway", x: 2544, y: 360, width: 240, height: 265 },
  ];
  const [path] = relationshipPath({ source: "agent", target: "gateway", sourceX: 2459.89, sourceY: -228.61,
    targetX: 2604.09, targetY: 491.39, sourcePosition: Position.Right, targetPosition: Position.Left }, boxes,
  { source: 14, target: 0 });
  const values = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
  for (let index = 0; index < values.length - 2; index += 6) for (let step = 0; step <= 400; step++) {
    const t = step / 400, u = 1 - t;
    const [x, y] = [0, 1].map(axis => u ** 3 * values[index + axis]! + 3 * u ** 2 * t * values[index + axis + 2]!
      + 3 * u * t ** 2 * values[index + axis + 4]! + t ** 3 * values[index + axis + 6]!);
    expect(boxes.slice(1, 3).some(box => x! > box.x && x! < box.x + box.width && y! > box.y && y! < box.y + box.height)).toBe(false);
  }
});
