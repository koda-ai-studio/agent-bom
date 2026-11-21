import { Position } from "@xyflow/react";
import { expect, it } from "vitest";
import { relationshipPath } from "@/lib/relationship-routing";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import { branchingFixture } from "./fixtures/attack-path-graph-fixture";
import { RELATIONSHIP_COLOR_MAP } from "@/lib/graph-schema";

it("uses relationship color and evidence style independently of reach score", () => {
  const { graph } = branchingFixture();
  const draw = (tier: string) => buildUnifiedFlowGraph({ ...graph, attack_paths: [], edges: [{ ...graph.edges[0]!,
    relationship: "contains", evidence: { tier, source: "test-collector", effective_reach_score: 99 },
  }] }, createExpandedGraphFilters()).edges[0]!;
  expect(draw("modeled_infrastructure").style?.strokeDasharray).toBeTruthy();
  expect(draw("runtime_observed").style?.strokeDasharray).toBeUndefined();
  expect(draw("modeled_infrastructure").style?.stroke).toBe(RELATIONSHIP_COLOR_MAP.contains);
});

const edge = { source: "a", target: "b", sourceX: 72, sourceY: 36, targetX: 672, targetY: 36,
  sourcePosition: Position.Right, targetPosition: Position.Left };
const obstacle = { id: "other", x: 260, y: 0, width: 220, height: 180 };

it.each([edge, { ...edge, sourceX: 672, targetX: 72, sourcePosition: Position.Left, targetPosition: Position.Right }])(
  "keeps a cubic curve and its label outside unrelated cards in either direction", endpoints => {
    const [path, labelX, labelY] = relationshipPath(endpoints, [obstacle]);
    expect(path).not.toMatch(/[LQ]/);
    const values = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
    expect(values).toHaveLength(8);
    expect(values.slice(0, 2)).toEqual([endpoints.sourceX, endpoints.sourceY]);
    expect(values.slice(-2)).toEqual([endpoints.targetX, endpoints.targetY]);
    const inside = (x: number, y: number) => x > obstacle.x - 12 && x < obstacle.x + obstacle.width + 12
      && y > obstacle.y - 12 && y < obstacle.y + obstacle.height + 12;
    expect(inside(labelX, labelY)).toBe(false);
    for (let step = 0; step <= 200; step++) {
      const t = step / 200, u = 1 - t;
      const point = [0, 1].map(axis => u ** 3 * values[axis]! + 3 * u ** 2 * t * values[axis + 2]!
        + 3 * u * t ** 2 * values[axis + 4]! + t ** 3 * values[axis + 6]!);
      expect(inside(point[0]!, point[1]!)).toBe(false);
    }
  },
);

it("does not move a clear curve merely because a distant card shares its bounding box", () => {
  const diagonal = { ...edge, sourceY: 300, targetY: 0 };
  expect(relationshipPath(diagonal, [{ id: "distant", x: 400, y: 240, width: 100, height: 80 }]))
    .toEqual(relationshipPath(diagonal, []));
});

it("uses a local gap through a dense map without crossing another card", () => {
  const cards = Array.from({ length: 21 }, (_, index) => ({ id: `card-${index}`, x: index % 7 * 370,
    y: (Math.floor(index / 7) + 1) * 340, width: 220, height: 224 }))
    .filter(card => !(card.x === 1480 && card.y === 340));
  const [path, labelX, labelY] = relationshipPath({ ...edge, sourceX: 1590, sourceY: 376,
    targetX: 1220, targetY: 1396, sourcePosition: Position.Left, targetPosition: Position.Top }, cards);
  expect(path).not.toMatch(/[LQ]/);
  const values = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
  const clear = (x: number, y: number) => cards.every(card => x <= card.x - 12 || x >= card.x + card.width + 12
    || y <= card.y - 12 || y >= card.y + card.height + 12);
  expect(clear(labelX, labelY)).toBe(true);
  for (let index = 0; index < values.length - 2; index += 6) {
    for (let step = 0; step <= 200; step++) {
      const t = step / 200, u = 1 - t;
      const [x, y] = [0, 1].map(axis => u ** 3 * values[index + axis]! + 3 * u ** 2 * t * values[index + axis + 2]!
        + 3 * u * t ** 2 * values[index + axis + 4]! + t ** 3 * values[index + axis + 6]!);
      expect(clear(x!, y!)).toBe(true);
      expect(x).toBeGreaterThan(0);
      expect(x).toBeLessThan(2440);
    }
  }
});
