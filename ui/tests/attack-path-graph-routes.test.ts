import { Position } from "@xyflow/react";
import { describe, expect, it } from "vitest";
import { buildAttackPathGraphModel, type AttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { layoutAttackPathGraph, type AttackPathDirection } from "@/lib/attack-path-graph-layout";
import { GLYPH_CENTER_Y, glyphInsetX, routeAttackPathEdges, type Point } from "@/lib/attack-path-graph-routes";
import { relationshipPath } from "@/lib/relationship-routing";
import { relationshipLaneFor } from "@/lib/relationship-lanes";
import { branchingFixture, demoFixture, fanOutFixture } from "./fixtures/attack-path-graph-fixture";

type Curve = [Point, Point, Point, Point];
function curves(path: string): Curve[] {
  const numbers = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
  const result: Curve[] = [];
  for (let i = 0; i < numbers.length - 2; i += 6) {
    result.push([0, 2, 4, 6].map(offset => ({ x: numbers[i + offset]!, y: numbers[i + offset + 1]! })) as Curve);
  }
  return result;
}
function samples(path: string): Point[] {
  return curves(path).flatMap(curve => Array.from({ length: 201 }, (_, step) => {
    const t = step / 200, u = 1 - t;
    return { x: u ** 3 * curve[0].x + 3 * u ** 2 * t * curve[1].x + 3 * u * t ** 2 * curve[2].x + t ** 3 * curve[3].x,
      y: u ** 3 * curve[0].y + 3 * u ** 2 * t * curve[1].y + 3 * u * t ** 2 * curve[2].y + t ** 3 * curve[3].y };
  }));
}

// Exercise the router used by AttackPathGraphEdge with the canvas's real glyph ports.
function routesFor(model: AttackPathGraphModel, direction: AttackPathDirection) {
  const layout = layoutAttackPathGraph(model, direction);
  const obstacles = [...layout.positions].map(([id, point]) => ({ id, ...point, width: layout.nodeWidth, height: layout.nodeHeight }));
  const laneEdges = model.edges.map(edge => ({ ...edge,
    sourceHandle: layout.positions.get(edge.source)!.x > layout.positions.get(edge.target)!.x ? "context" : null,
    targetHandle: layout.positions.get(edge.source)!.x > layout.positions.get(edge.target)!.x ? "context" : null }));
  const routes = new Map(model.edges.map(edge => {
    const source = layout.positions.get(edge.source)!, target = layout.positions.get(edge.target)!;
    const reverse = source.x > target.x, inset = glyphInsetX(layout.nodeWidth);
    const endpoints = { source: edge.source, target: edge.target,
      sourceX: source.x + (reverse ? inset : layout.nodeWidth - inset), sourceY: source.y + GLYPH_CENTER_Y,
      targetX: target.x + (reverse ? layout.nodeWidth - inset : inset), targetY: target.y + GLYPH_CENTER_Y,
      sourcePosition: reverse ? Position.Left : Position.Right, targetPosition: reverse ? Position.Right : Position.Left };
    const lane = relationshipLaneFor(edge.id, laneEdges, id => layout.positions.get(id)?.y, id => layout.positions.get(id)?.x);
    const [path] = relationshipPath(endpoints, obstacles, lane);
    return [edge.id, { path, endpoints, lane }];
  }));
  return { layout, routes };
}

// A crossing at a point is distinct from an overlapping straight trunk.
function straightRuns(path: string): [Point, Point][] {
  return curves(path).filter(curve => {
    const dx = curve[3].x - curve[0].x, dy = curve[3].y - curve[0].y;
    return curve.slice(1, 3).every(p => Math.abs((p.x - curve[0].x) * dy - (p.y - curve[0].y) * dx) < 0.01);
  }).map(curve => [curve[0], curve[3]]);
}
function sharedLength([a, b]: [Point, Point], [c, d]: [Point, Point]): number {
  const dx = b.x - a.x, dy = b.y - a.y, length = Math.hypot(dx, dy);
  if (length < 1) return 0;
  if ([c, d].some(p => Math.abs((p.x - a.x) * dy - (p.y - a.y) * dx) / length > 0.1)) return 0;
  const at = (p: Point) => ((p.x - a.x) * dx + (p.y - a.y) * dy) / length;
  return Math.max(0, Math.min(length, Math.max(at(c), at(d))) - Math.max(0, Math.min(at(c), at(d))));
}
const CASES = {
  "demo headline": () => demoFixture("headline"),
  "demo runbook (branched both ways)": () => demoFixture("runbook"),
  branching: () => branchingFixture(),
  "expanded fan-out": () => fanOutFixture(5),
};

describe("selected path relationship curves", () => {
  for (const [name, fixture] of Object.entries(CASES)) for (const direction of ["LR", "TB"] as const) {
    it(`draws individual curves without shared trunks: ${name} ${direction}`, () => {
      const { graph, selected } = fixture();
      const model = buildAttackPathGraphModel(graph, selected, { expandedGroups: new Set(["group:server:s:cloud_resource"]) });
      const { routes } = routesFor(model, direction);
      expect(routes.size).toBe(model.edges.length);
      const paths = [...routes.values()].map(route => route.path);
      expect(new Set(paths).size).toBe(paths.length);
      for (const path of paths) { expect(path).toContain("C"); expect(path).not.toMatch(/[LQ]/); }
      const runs = paths.map(straightRuns);
      for (let i = 0; i < runs.length; i++) for (let j = i + 1; j < runs.length; j++) {
        for (const a of runs[i]!) for (const b of runs[j]!) expect(sharedLength(a, b)).toBeLessThan(20);
      }
    });
  }

  it("connects every directed or bidirectional edge to its recorded source and target ports", () => {
    for (const fixture of Object.values(CASES)) {
      const { graph, selected } = fixture();
      const model = buildAttackPathGraphModel(graph, selected);
      const { routes } = routesFor(model, "LR");
      for (const edge of model.edges) {
        const { path, endpoints, lane } = routes.get(edge.id)!;
        const points = samples(path);
        expect(points[0], edge.id).toEqual({ x: endpoints.sourceX, y: endpoints.sourceY + lane.source });
        expect(points.at(-1), edge.id).toEqual({ x: endpoints.targetX, y: endpoints.targetY + lane.target });
        const sourceDirection = endpoints.sourcePosition === Position.Right ? 1 : -1;
        const targetDirection = endpoints.targetPosition === Position.Left ? 1 : -1;
        expect((points[1]!.x - points[0]!.x) * sourceDirection, edge.id).toBeGreaterThan(0);
        expect((points.at(-1)!.x - points.at(-2)!.x) * targetDirection, edge.id).toBeGreaterThan(0);
      }
    }
  });

  it("keeps reverse semantic-column edges directional and clear of intervening nodes", () => {
    const { graph, selected } = demoFixture("headline");
    // Reverse an existing selected edge, independently of the fixture's layer order.
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const ordered = [...layout.positions].sort((a, b) => a[1].x - b[1].x);
    const source = ordered.at(-1)![0], target = ordered[0]![0];
    const back = { ...model.edges[0]!, id: "back", source, target, bidirectional: false };
    const { routes } = routesFor({ ...model, edges: [...model.edges, back] }, "LR");
    const route = routes.get("back")!;
    expect(route.endpoints.sourcePosition).toBe(Position.Left);
    expect(route.endpoints.targetPosition).toBe(Position.Right);
    const points = samples(route.path);
    for (const [id, point] of layout.positions) if (id !== source && id !== target) {
      expect(points.some(p => p.x > point.x + 1 && p.x < point.x + layout.nodeWidth - 1
        && p.y > point.y + 1 && p.y < point.y + layout.nodeHeight - 1), id).toBe(false);
    }
  });

  for (const [name, fixture] of Object.entries(CASES)) for (const direction of ["LR", "TB"] as const) {
    it(`keeps curves clear of names and unrelated nodes: ${name} ${direction}`, () => {
      const { graph, selected } = fixture();
      const model = buildAttackPathGraphModel(graph, selected, { expandedGroups: new Set(["group:server:s:cloud_resource"]) });
      const { layout, routes } = routesFor(model, direction);
      const problems: string[] = [];
      for (const edge of model.edges) {
        const points = samples(routes.get(edge.id)!.path);
        for (const [id, position] of layout.positions) {
          const own = id === edge.source || id === edge.target;
          const top = position.y + (own ? 62 : 0);
          if (points.some(p => p.x > position.x + 1 && p.x < position.x + layout.nodeWidth - 1
            && p.y > top + 1 && p.y < position.y + layout.nodeHeight - 1)) problems.push(`${edge.id} crosses ${id}`);
        }
      }
      expect(problems).toEqual([]);
    });
  }

  it("gives fan-out links distinct ports and pair channels instead of a shared trunk", () => {
    const { graph, selected } = fanOutFixture(5);
    const model = buildAttackPathGraphModel(graph, selected, { collapseThreshold: 100 });
    const { routes } = routesFor(model, "LR");
    const outgoing = model.edges.filter(edge => edge.source === "server:s").map(edge => routes.get(edge.id)!);
    expect(outgoing.length).toBeGreaterThan(1);
    expect(new Set(outgoing.map(route => `${route.endpoints.sourceX}:${route.endpoints.sourceY + route.lane.source}`)).size).toBe(outgoing.length);
    expect(new Set(outgoing.map(route => route.path)).size).toBe(outgoing.length);
  });
});

// Canvas framing must not change the relative geometry of route channels.
it("translates every route channel with the occupied node columns", () => {
  const { graph, selected } = demoFixture("runbook");
  const model = buildAttackPathGraphModel(graph, selected);
  const layout = layoutAttackPathGraph(model, "LR");
  const routes = routeAttackPathEdges(model, layout);
  const shifted = { ...layout, positions: new Map([...layout.positions].map(([id, point]) => [id, { ...point, x: point.x + 1234 }])) };
  const actual = routeAttackPathEdges(model, shifted);
  for (const [id, points] of routes) {
    expect(actual.get(id), id).toEqual(points.map(point => ({ ...point, x: point.x + 1234 })));
  }
});
