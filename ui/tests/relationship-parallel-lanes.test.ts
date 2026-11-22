import { Position } from "@xyflow/react";
import { describe, expect, it } from "vitest";
import { LANE_GAP, relationshipLaneFor } from "@/lib/relationship-lanes";
import { relationshipPath } from "@/lib/relationship-routing";

type Point = { x: number; y: number };
/** Sample the rendered cubics, rather than treating control points as line segments. */
const points = (path: string): Point[] => {
  const values = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
  const result: Point[] = [];
  for (let index = 0; index < values.length - 2; index += 6) for (let step = 0; step <= 100; step++) {
    const t = step / 100, u = 1 - t;
    const coordinate = (axis: number) => u ** 3 * values[index + axis]! + 3 * u ** 2 * t * values[index + axis + 2]!
      + 3 * u * t ** 2 * values[index + axis + 4]! + t ** 3 * values[index + axis + 6]!;
    result.push({ x: coordinate(0), y: coordinate(1) });
  }
  return result;
};
const cross = (a: Point, b: Point, c: Point) => (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
const segments = (path: string) => { const list = points(path); return list.slice(1).map((point, index) => [list[index]!, point] as const); };
function sharedLength(a: string, b: string): number {
  let shared = 0;
  for (const [p, q] of segments(a)) for (const [r, s] of segments(b)) {
    if (Math.abs(cross(p, q, r)) > 0.00001 || Math.abs(cross(p, q, s)) > 0.00001) continue;
    const length = Math.hypot(q.x - p.x, q.y - p.y);
    if (length === 0) continue;
    const along = (point: Point) => ((point.x - p.x) * (q.x - p.x) + (point.y - p.y) * (q.y - p.y)) / length;
    shared += Math.max(0, Math.min(length, Math.max(along(r), along(s))) - Math.max(0, Math.min(along(r), along(s))));
  }
  return shared;
}
function curvesCross(a: string, b: string): boolean {
  return segments(a).some(([p, q]) => segments(b).some(([r, s]) =>
    cross(p, q, r) * cross(p, q, s) < -0.00001 && cross(r, s, p) * cross(r, s, q) < -0.00001));
}

// The mesh capture: developer-copilot uses two MCP servers and a role can access it,
// all drawn from the agent's right-hand port toward a column on the right.
const nodeY: Record<string, number> = { copilot: 522, filesystem: 367, github: 522, role: 680 };
const edges = [
  { id: "uses-fs", source: "copilot", target: "filesystem", sourceHandle: "right", targetHandle: "left", data: { relationship: "uses" } },
  { id: "uses-gh", source: "copilot", target: "github", sourceHandle: "right", targetHandle: "left", data: { relationship: "uses" } },
  { id: "access", source: "copilot", target: "role", sourceHandle: "right", targetHandle: "left", data: { relationship: "can_access" } },
];
const yOf = (id: string) => nodeY[id];

describe("parallel relationship lanes", () => {
  it("gives each source-target pair a distinct lane even for one relationship type", () => {
    expect(relationshipLaneFor("uses-fs", edges, yOf).source).not.toBe(relationshipLaneFor("uses-gh", edges, yOf).source);
  });

  it("gives a different relationship type leaving the same port its own lane", () => {
    const uses = relationshipLaneFor("uses-gh", edges, yOf);
    const access = relationshipLaneFor("access", edges, yOf);
    expect(access.source).not.toBe(uses.source);
    // The type whose targets sit lower takes the lower lane.
    expect(access.source).toBeGreaterThan(uses.source);
  });

  it("centres a pair of distinct connections around their shared port", () => {
    const single = edges.filter(edge => edge.data.relationship === "uses");
    expect(relationshipLaneFor("uses-fs", single, yOf)).toEqual({ source: -LANE_GAP / 2, target: 0 });
    expect(relationshipLaneFor("uses-gh", single, yOf)).toEqual({ source: LANE_GAP / 2, target: 0 });
  });

  it("ignores hidden edges", () => {
    const hidden = edges.map(edge => edge.id === "access" ? { ...edge, hidden: true } : edge);
    expect(relationshipLaneFor("uses-fs", hidden, yOf)).toEqual(relationshipLaneFor("uses-fs", hidden.filter(edge => !("hidden" in edge && edge.hidden)), yOf));
  });

  it("draws two relationship types from one port without a shared run", () => {
    const sourceX = 578, sourceY = 522, targetX = 915;
    const base = { source: "copilot", sourceX, sourceY, sourcePosition: Position.Right, targetPosition: Position.Left };
    const usesFs = relationshipPath({ ...base, target: "filesystem", targetX, targetY: 367 }, [], relationshipLaneFor("uses-fs", edges, yOf))[0];
    const usesGh = relationshipPath({ ...base, target: "github", targetX, targetY: 522 }, [], relationshipLaneFor("uses-gh", edges, yOf))[0];
    const access = relationshipPath({ ...base, target: "role", targetX, targetY: 680 }, [], relationshipLaneFor("access", edges, yOf))[0];
    expect(sharedLength(access, usesFs)).toBe(0);
    expect(sharedLength(access, usesGh)).toBe(0);
    // The same relationship kind never creates a shared trunk.
    expect(sharedLength(usesFs, usesGh)).toBe(0);
  });

  it("keeps an incoming relationship off the lane of outgoing ones on the same side of a card", () => {
    // The mesh capture as recorded: the role can access the agent, a backward edge drawn
    // from the role's left port into the agent's right port, beside the agent's own Uses lines.
    const mesh = [
      { id: "uses-fs", source: "copilot", target: "filesystem", data: { relationship: "uses" } },
      { id: "uses-gh", source: "copilot", target: "github", data: { relationship: "uses" } },
      { id: "access", source: "role", target: "copilot", sourceHandle: "context", targetHandle: "context", data: { relationship: "can_access" } },
    ];
    const uses = relationshipLaneFor("uses-gh", mesh, yOf);
    const access = relationshipLaneFor("access", mesh, yOf);
    expect(access.target).not.toBe(uses.source);
    const forward = { source: "copilot", sourceX: 578, sourceY: 522, sourcePosition: Position.Right, targetPosition: Position.Left };
    const usesFs = relationshipPath({ ...forward, target: "filesystem", targetX: 915, targetY: 367 }, [], relationshipLaneFor("uses-fs", mesh, yOf))[0];
    const usesGh = relationshipPath({ ...forward, target: "github", targetX: 915, targetY: 522 }, [], uses)[0];
    const accessPath = relationshipPath({ source: "role", target: "copilot", sourceX: 915, sourceY: 680, targetX: 578, targetY: 522,
      sourcePosition: Position.Left, targetPosition: Position.Right }, [], access)[0];
    expect(sharedLength(accessPath, usesFs)).toBe(0);
    expect(sharedLength(accessPath, usesGh)).toBe(0);
    // The backward line still starts at the role and ends at the agent.
    const route = points(accessPath);
    expect(route[0]!.x).toBe(915);
    expect(route.at(-1)!.x).toBe(578);
  });

  it("keeps distinct approaches to one measured port, even when one link runs along the row", () => {
    // The reference correlation: the server exposes the agent from a row above; the container on the agent's row contains it.
    const at: Record<string, { x: number; y: number }> = { server: { x: 0, y: 307 }, instance1: { x: 0, y: 465 }, agent: { x: 370, y: 465 } };
    const links = [
      { id: "exposed", source: "server", target: "agent", data: { relationship: "exposed_to" } },
      { id: "contains", source: "instance1", target: "agent", data: { relationship: "contains" } },
    ];
    const end = (id: string) => {
      const link = links.find(item => item.id === id)!;
      const route = relationshipPath({ source: link.source, target: link.target, sourceX: 100, sourceY: at[link.source]!.y,
        targetX: 680, targetY: at.agent!.y, sourcePosition: Position.Right, targetPosition: Position.Left },
      [], relationshipLaneFor(id, links, node => at[node]?.y, node => at[node]?.x))[0];
      return route;
    };
    const exposed = end("exposed"), contains = end("contains");
    expect(points(exposed).at(-1)).toEqual(points(contains).at(-1));
    expect(sharedLength(exposed, contains)).toBe(0);
    expect(Math.abs(points(exposed)[50]!.y - points(contains)[50]!.y)).toBeGreaterThanOrEqual(LANE_GAP);
  });

  it("keeps two same-direction lanes from crossing each other", () => {
    const lanes = [
      { id: "near", source: "a", target: "b", sourceHandle: "r", targetHandle: "l", data: { relationship: "uses" } },
      { id: "far", source: "a", target: "c", sourceHandle: "r", targetHandle: "l", data: { relationship: "can_access" } },
    ];
    const ys: Record<string, number> = { a: 0, b: 200, c: 400 };
    const base = { source: "a", sourceX: 0, sourceY: 0, sourcePosition: Position.Right, targetPosition: Position.Left };
    const near = relationshipPath({ ...base, target: "b", targetX: 400, targetY: 200 }, [], relationshipLaneFor("near", lanes, id => ys[id]))[0];
    const far = relationshipPath({ ...base, target: "c", targetX: 400, targetY: 400 }, [], relationshipLaneFor("far", lanes, id => ys[id]))[0];
    const crossing = curvesCross(near, far);
    expect(crossing).toBe(false);
    expect(sharedLength(near, far)).toBe(0);
  });

  it("turns edges bound for different targets in their own channels", () => {
    // The reference correlation: a server and a container feed the agent; two containers and a pin feed pillow.
    const at: Record<string, { x: number; y: number }> = {
      server: { x: 0, y: 307 }, instance1: { x: 0, y: 465 }, pin: { x: 0, y: 621 }, instance2: { x: 0, y: 778 },
      agent: { x: 370, y: 465 }, pillow: { x: 370, y: 633 },
    };
    const links = [
      { id: "server-agent", source: "server", target: "agent", data: { relationship: "uses" } },
      { id: "instance1-agent", source: "instance1", target: "agent", data: { relationship: "runs" } },
      { id: "instance1-pillow", source: "instance1", target: "pillow", data: { relationship: "contains" } },
      { id: "pin-pillow", source: "pin", target: "pillow", data: { relationship: "declares" } },
      { id: "instance2-pillow", source: "instance2", target: "pillow", data: { relationship: "contains" } },
    ];
    const route = (id: string) => {
      const link = links.find(item => item.id === id)!;
      return relationshipPath({ source: link.source, target: link.target, sourceX: 100, sourceY: at[link.source]!.y,
        targetX: 680, targetY: at[link.target]!.y, sourcePosition: Position.Right, targetPosition: Position.Left },
      [], relationshipLaneFor(id, links, node => at[node]?.y, node => at[node]?.x));
    };
    // Channels belong to source-target pairs, not only to targets.
    expect(relationshipLaneFor("server-agent", links, node => at[node]?.y, node => at[node]?.x).channel)
      .not.toBe(relationshipLaneFor("instance1-agent", links, node => at[node]?.y, node => at[node]?.x).channel);
    expect(sharedLength(route("server-agent")[0], route("instance2-pillow")[0])).toBe(0);
    expect(sharedLength(route("server-agent")[0], route("instance1-pillow")[0])).toBe(0);
    // Different sources remain separate all the way to the target.
    expect(sharedLength(route("instance1-pillow")[0], route("instance2-pillow")[0])).toBe(0);
    // A line never ends off its target's port row by more than one lane.
    for (const id of ["pin-pillow", "instance1-pillow", "instance2-pillow"]) {
      const end = points(route(id)[0]).at(-1)!;
      expect(Math.abs(end.y - at.pillow!.y)).toBeLessThanOrEqual(LANE_GAP);
    }
  });

  it("nests downward channels so a nearer target's line never crosses a farther one", () => {
    const at: Record<string, { x: number; y: number }> = { a: { x: 0, y: 0 }, b: { x: 0, y: 40 }, near: { x: 370, y: 200 }, far: { x: 370, y: 400 } };
    const links = [
      { id: "a-near", source: "a", target: "near", data: { relationship: "uses" } },
      { id: "b-far", source: "b", target: "far", data: { relationship: "uses" } },
    ];
    const route = (id: string) => {
      const link = links.find(item => item.id === id)!;
      return relationshipPath({ source: link.source, target: link.target, sourceX: 0, sourceY: at[link.source]!.y,
        targetX: 400, targetY: at[link.target]!.y, sourcePosition: Position.Right, targetPosition: Position.Left },
      [], relationshipLaneFor(id, links, node => at[node]?.y, node => at[node]?.x))[0];
    };
    const crossing = curvesCross(route("a-near"), route("b-far"));
    expect(crossing).toBe(false);
  });

  it("does not change a route that has no lane", () => {
    const edge = { source: "a", target: "b", sourceX: 0, sourceY: 0, targetX: 400, targetY: 200,
      sourcePosition: Position.Right, targetPosition: Position.Left };
    expect(relationshipPath(edge, [], { source: 0, target: 0 })).toEqual(relationshipPath(edge, []));
  });
});
