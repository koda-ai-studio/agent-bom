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

/**
 * Crossings between different edges. Two lines that share a node may only
 * meet at the handle they share (within 2px); a crossing anywhere else, even
 * right beside the shared node, counts.
 */
function crossings(model: AttackPathGraphModel, direction: AttackPathDirection): string[] {
  const layout = layoutAttackPathGraph(model, direction);
  const routes = routeAttackPathEdges(model, layout);
  const sampled = model.edges.map(edge => ({ edge, points: sampleRoute(routes.get(edge.id)!) }));
  const out: string[] = [];
  for (let i = 0; i < sampled.length; i += 1) {
    for (let j = i + 1; j < sampled.length; j += 1) {
      const a = sampled[i]!, b = sampled[j]!;
      const ends = (points: Point[]) => [points[0]!, points.at(-1)!];
      const common = ends(a.points).filter(p => ends(b.points).some(q => Math.hypot(p.x - q.x, p.y - q.y) < 2));
      const nearShared = (p: Point) => common.some(anchor => Math.hypot(anchor.x - p.x, anchor.y - p.y) < 2);
      for (let s = 0; s < a.points.length - 1; s += 1) {
        for (let t = 0; t < b.points.length - 1; t += 1) {
          const sa: Segment = [a.points[s]!, a.points[s + 1]!], sb: Segment = [b.points[t]!, b.points[t + 1]!];
          if (properlyIntersect(sa, sb) && !(nearShared(sa[0]) || nearShared(sa[1]))) out.push(`${a.edge.id} x ${b.edge.id} @${Math.round(sa[0].x)},${Math.round(sa[0].y)}`);
        }
      }
      // Two lines running on top of each other and then splitting read as a crossing too. Lines fanning out of
      // (or into) one handle may only touch on the leg at that handle; past their first turn they must be apart.
      const isCommon = (p: Point) => common.some(anchor => Math.hypot(anchor.x - p.x, anchor.y - p.y) < 2);
      const tail = (item: typeof a) => {
        let route = routes.get(item.edge.id)!;
        if (isCommon(route[0]!)) route = route.slice(1);
        if (isCommon(route.at(-1)!)) route = route.slice(0, -1);
        return route.length >= 2 ? sampleRoute(route) : [];
      };
      const bDense = densify(tail(b));
      const merged = densify(tail(a)).find(p => !common.some(anchor => Math.hypot(anchor.x - p.x, anchor.y - p.y) < 2)
        && bDense.some(q => Math.hypot(p.x - q.x, p.y - q.y) < 1.5));
      if (merged) out.push(`${a.edge.id} merges ${b.edge.id} @${Math.round(merged.x)},${Math.round(merged.y)}`);
    }
  }
  return [...new Set(out)];
}

function densify(points: Point[], step = 2): Point[] {
  const out: Point[] = [];
  for (let index = 1; index < points.length; index += 1) {
    const a = points[index - 1]!, b = points[index]!;
    const count = Math.max(1, Math.ceil(Math.hypot(b.x - a.x, b.y - a.y) / step));
    for (let k = 0; k <= count; k += 1) out.push({ x: a.x + ((b.x - a.x) * k) / count, y: a.y + ((b.y - a.y) * k) / count });
  }
  return out;
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
        const points = sampleRoute(routes.get(edge.id)!);
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
    // Past the turns out of the source's row and into the target's row, the line runs outside every row.
    const runs = route.slice(1, -1).filter(point => point.y !== route[0]!.y && point.y !== route.at(-1)!.y);
    expect(runs.length).toBeGreaterThan(0);
    for (const point of runs) expect(point.y < lanesTop || point.y > lanesBottom).toBe(true);
  });

  /** Where the glyph ends and the name begins inside a node box (6px top inset + 56px glyph). */
  const NAME_TOP = 62;

  for (const [name, fixture] of Object.entries(CASES)) {
    for (const direction of ["LR", "TB"] as const) {
      it(`keeps every line clear of node names and of nodes it does not connect: ${name} ${direction}`, () => {
        const { graph, selected } = fixture();
        const model = buildAttackPathGraphModel(graph, selected, { expandedGroups: new Set(["group:server:s:cloud_resource"]) });
        const layout = layoutAttackPathGraph(model, direction);
        const routes = routeAttackPathEdges(model, layout);
        const problems: string[] = [];
        for (const edge of model.edges) {
          const points = densify(sampleRoute(routes.get(edge.id)!));
          for (const [id, position] of layout.positions) {
            const inside = (p: Point, top: number) => p.x > position.x + 1 && p.x < position.x + layout.nodeWidth - 1 && p.y > top + 1 && p.y < position.y + layout.nodeHeight - 1;
            const own = id === edge.source || id === edge.target;
            const hit = points.find(p => inside(p, own ? position.y + NAME_TOP : position.y));
            if (hit) problems.push(`${edge.id} ${own ? "runs through the name of" : "crosses"} ${id} @${Math.round(hit.x)},${Math.round(hit.y)}`);
          }
        }
        expect(problems).toEqual([]);
      });
    }
  }

  it("gives each line fanning out of one node its own turn instead of a shared trunk", () => {
    const { graph, selected } = fanOutFixture(5);
    const model = buildAttackPathGraphModel(graph, selected, { collapseThreshold: 100 });
    const layout = layoutAttackPathGraph(model, "LR");
    const routes = routeAttackPathEdges(model, layout);
    const bySource = new Map<string, number[]>();
    for (const edge of model.edges) {
      const route = routes.get(edge.id)!;
      if (route.length < 3) continue;
      bySource.set(edge.source, [...(bySource.get(edge.source) ?? []), route[1]!.x]);
    }
    const fanned = [...bySource.values()].filter(turns => turns.length > 1);
    expect(fanned.length).toBeGreaterThan(0);
    for (const turns of fanned) {
      const sorted = [...turns].sort((a, b) => a - b);
      for (let index = 1; index < sorted.length; index += 1) expect(sorted[index]! - sorted[index - 1]!).toBeGreaterThanOrEqual(6);
    }
  });
});
