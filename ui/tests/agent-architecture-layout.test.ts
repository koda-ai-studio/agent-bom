import { describe, expect, it } from "vitest";

import { buildArchitectureModel, COLLAPSE_AFTER } from "@/lib/agent-architecture-model";
import { architectureCanvasHeight, countRouteCrossings, layoutArchitecture, routeArchitecture } from "@/lib/agent-architecture-layout";
import { agentByLabel, crewHarness, supervisorHarness, toolTeamHarness, wideCrew } from "./fixtures/agent-architecture-fixture";

const none = new Set<string>();
const harnesses = () => [supervisorHarness(), toolTeamHarness(), crewHarness(), wideCrew(COLLAPSE_AFTER + 2)];

function overlaps(layout: ReturnType<typeof layoutArchitecture>): number {
  const boxes = [...layout.positions.values()];
  let count = 0;
  for (let i = 0; i < boxes.length; i += 1) for (let j = i + 1; j < boxes.length; j += 1) {
    const a = boxes[i]!, b = boxes[j]!;
    if (a.x < b.x + layout.nodeWidth && b.x < a.x + layout.nodeWidth && a.y < b.y + layout.nodeHeight && b.y < a.y + layout.nodeHeight) count += 1;
  }
  return count;
}

describe("agent architecture layout", () => {
  it("stacks layers top to bottom: harness, then orchestrators and sub-agents by layer", () => {
    const harness = supervisorHarness();
    const model = buildArchitectureModel(harness, { mode: "layered", expanded: none });
    const layout = layoutArchitecture(model);
    expect(layout.direction).toBe("TB");
    const y = (label: string) => layout.positions.get(agentByLabel(harness, label).id)!.y;
    expect(y("builder")).toBeLessThan(y("supervisor"));
    expect(y("supervisor")).toBe(y("writer"));
    expect(y("research")).toBeLessThan(y("research_builder"));
    expect(y("research_builder")).toBeLessThan(y("search"));
    expect(y("search")).toBe(y("summarize"));
    // A parent sits centred over its children.
    const x = (label: string) => layout.positions.get(agentByLabel(harness, label).id)!.x;
    expect(x("research_builder")).toBeCloseTo((x("search") + x("summarize")) / 2);
  });

  it("reads the flow left to right from the entry to the finish", () => {
    const harness = supervisorHarness();
    const model = buildArchitectureModel(harness, { mode: "flow", expanded: none });
    const layout = layoutArchitecture(model);
    expect(layout.direction).toBe("LR");
    const x = (id: string) => layout.positions.get(id)!.x;
    for (const edge of model.edges) expect(x(edge.target)).toBeGreaterThan(x(edge.source));
    const end = model.nodes.find(node => node.label === "End")!;
    expect(x(end.id)).toBe(Math.max(...[...layout.positions.values()].map(point => point.x)));
  });

  it("keeps generous spacing and never overlaps nodes", () => {
    for (const harness of harnesses()) for (const mode of ["layered", "flow"] as const) {
      const layout = layoutArchitecture(buildArchitectureModel(harness, { mode, expanded: none }));
      expect(overlaps(layout)).toBe(0);
      expect(layout.rankGap).toBeGreaterThanOrEqual(64);
      expect(layout.laneGap).toBeGreaterThanOrEqual(32);
    }
  });

  it("draws no crossing connectors on the fixtures", () => {
    for (const harness of harnesses()) for (const mode of ["layered", "flow"] as const) {
      const model = buildArchitectureModel(harness, { mode, expanded: none });
      const layout = layoutArchitecture(model);
      const routes = routeArchitecture(model, layout);
      expect(routes.size).toBe(model.edges.length);
      expect(countRouteCrossings(model, routes)).toBe(0);
    }
  });

  it("counts a crossing when two connectors do cross", () => {
    const harness = crewHarness();
    const model = buildArchitectureModel(harness, { mode: "flow", expanded: none });
    const [a, b] = model.edges;
    const routes = new Map([[a!.id, [{ x: 0, y: 0 }, { x: 100, y: 100 }]], [b!.id, [{ x: 0, y: 100 }, { x: 100, y: 0 }]]]);
    const crossed = { ...model, edges: [{ ...a!, source: "p", target: "q" }, { ...b!, source: "r", target: "s" }] };
    expect(countRouteCrossings(crossed, routes)).toBe(1);
  });

  it("sizes the canvas to its content within readable bounds", () => {
    const small = layoutArchitecture(buildArchitectureModel(crewHarness(), { mode: "layered", expanded: none }));
    const large = layoutArchitecture(buildArchitectureModel(supervisorHarness(), { mode: "layered", expanded: none }));
    const smallHeight = architectureCanvasHeight(small, 1200);
    const largeHeight = architectureCanvasHeight(large, 1200);
    expect(smallHeight).toBeGreaterThanOrEqual(320);
    expect(largeHeight).toBeGreaterThan(smallHeight);
    expect(largeHeight).toBeLessThanOrEqual(860);
  });
});
