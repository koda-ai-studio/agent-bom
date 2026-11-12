import { describe, expect, it } from "vitest";

import { buildAttackPathGraphModel, type AttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { layoutAttackPathGraph, type AttackPathDirection } from "@/lib/attack-path-graph-layout";
import { routeAttackPathEdges, sampleRoute, type Point } from "@/lib/attack-path-graph-routes";
import { branchingFixture, demoFixture, fanOutFixture } from "./fixtures/attack-path-graph-fixture";

type Segment = [Point, Point];

function properlyIntersect([a, b]: Segment, [c, d]: Segment): boolean {
  const orient = (p: Point, q: Point, r: Point) => Math.sign((q.x - p.x) * (r.y - p.y) - (q.y - p.y) * (r.x - p.x));
  const o1 = orient(a, b, c), o2 = orient(a, b, d), o3 = orient(c, d, a), o4 = orient(c, d, b);
  return o1 * o2 < 0 && o3 * o4 < 0;
}

/** Crossings between different edges, ignoring the fan-out right at a node they share. */
function crossings(model: AttackPathGraphModel, direction: AttackPathDirection): string[] {
  const layout = layoutAttackPathGraph(model, direction);
  const routes = routeAttackPathEdges(model, layout);
  const sampled = model.edges.map(edge => ({ edge, points: sampleRoute(routes.get(edge.id)!, direction) }));
  const out: string[] = [];
  for (let i = 0; i < sampled.length; i += 1) {
    for (let j = i + 1; j < sampled.length; j += 1) {
      const a = sampled[i]!, b = sampled[j]!;
      const shared = [a.edge.source, a.edge.target].filter(id => id === b.edge.source || id === b.edge.target);
      const anchors = [...a.points.slice(0, 1), ...a.points.slice(-1), ...b.points.slice(0, 1), ...b.points.slice(-1)];
      const nearShared = (p: Point) => shared.length > 0 && anchors.some(anchor => Math.hypot(anchor.x - p.x, anchor.y - p.y) < 64);
      for (let s = 0; s < a.points.length - 1; s += 1) {
        for (let t = 0; t < b.points.length - 1; t += 1) {
          const sa: Segment = [a.points[s]!, a.points[s + 1]!], sb: Segment = [b.points[t]!, b.points[t + 1]!];
          if (properlyIntersect(sa, sb) && !(nearShared(sa[0]) || nearShared(sa[1]))) out.push(`${a.edge.id} x ${b.edge.id} @${Math.round(sa[0].x)},${Math.round(sa[0].y)}`);
        }
      }
    }
  }
  return [...new Set(out)];
}

const CASES = {
  "demo headline": () => demoFixture("headline"),
  "demo runbook (branched both ways)": () => demoFixture("runbook"),
  branching: () => branchingFixture(),
  "expanded fan-out": () => fanOutFixture(5),
};

describe("attack path edge routing", () => {
  for (const [name, fixture] of Object.entries(CASES)) {
    for (const direction of ["LR", "TB"] as const) {
      it(`draws no crossing edges: ${name} ${direction}`, () => {
        const { graph, selected } = fixture();
        const model = buildAttackPathGraphModel(graph, selected, { expandedGroups: new Set(["group:server:s:cloud_resource"]) });
        expect(crossings(model, direction)).toEqual([]);
      });
    }
  }

  it("enters every node from its leading side, so no arrow points back into the spine", () => {
    for (const fixture of Object.values(CASES)) {
      const { graph, selected } = fixture();
      const model = buildAttackPathGraphModel(graph, selected);
      const layout = layoutAttackPathGraph(model, "LR");
      const routes = routeAttackPathEdges(model, layout);
      for (const edge of model.edges) {
        const points = sampleRoute(routes.get(edge.id)!, "LR");
        const [before, end] = points.slice(-2) as [Point, Point];
        const [start, after] = points.slice(0, 2) as [Point, Point];
        // Arrives moving right into the target's left side; leaves moving right from the source's right side.
        expect(end.x - before.x, edge.id).toBeGreaterThan(0);
        expect(after.x - start.x, edge.id).toBeGreaterThan(0);
        const target = layout.positions.get(edge.target)!;
        expect(end.x, edge.id).toBeLessThan(target.x + layout.nodeWidth / 2);
      }
    }
  });

  it("routes a recorded edge that runs against the layer order around the outside of the rows", () => {
    const { graph, selected } = demoFixture("headline");
    const backward = { ...graph, edges: [...graph.edges, { ...graph.edges[0]!, id: "back", source: "server:github", target: "sa:jit", relationship: "uses", direction: "directed" as const }] };
    const model = buildAttackPathGraphModel(backward, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const route = routeAttackPathEdges(model, layout).get("back")!;
    const lanesTop = Math.min(...[...layout.positions.values()].map(position => position.y));
    const lanesBottom = Math.max(...[...layout.positions.values()].map(position => position.y + layout.nodeHeight));
    const runs = route.slice(1, -1);
    expect(runs.length).toBeGreaterThan(0);
    for (const point of runs) expect(point.y < lanesTop || point.y > lanesBottom).toBe(true);
  });
});
