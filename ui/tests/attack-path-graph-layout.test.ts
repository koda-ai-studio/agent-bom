import { describe, expect, it } from "vitest";

import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import {
  ATTACK_PATH_CANVAS_BOUNDS,
  NARROW_MIN_ZOOM,
  attackPathCanvasHeight,
  attackPathCanvasWidth,
  narrowFitZoom,
  layoutAttackPathGraph,
} from "@/lib/attack-path-graph-layout";
import { attackPathViewport } from "@/lib/attack-path-graph-viewport";
import { branchingFixture, demoFixture, fanOutFixture } from "./fixtures/attack-path-graph-fixture";

describe("attack path graph layout", () => {
  it("puts a branch server's package beside the server, not in a loop below it; a path hop's package stays below the hop", () => {
    const node = (id: string, semanticLayer: string, semanticOwner?: string) => ({ id, entityType: semanticLayer, semanticLayer, ...(semanticOwner ? { semanticOwner } : {}) });
    const link = (source: string, target: string, relationship: string) => ({ id: `${source}->${target}`, source, target, relationship });
    const model = {
      pathNodeIds: ["agent", "gateway", "pkg", "cve"],
      nodes: [node("agent", "orchestration"), node("gateway", "mcp_server"), node("pkg", "package"), node("cve", "finding"),
        node("server", "mcp_server"), node("helper", "package", "server"), node("lib", "package", "gateway")],
      edges: [link("agent", "gateway", "uses"), link("gateway", "pkg", "depends_on"), link("pkg", "cve", "vulnerable_to"),
        link("agent", "server", "uses"), link("server", "helper", "depends_on"), link("gateway", "lib", "depends_on")],
    } as unknown as Parameters<typeof layoutAttackPathGraph>[0];
    const layout = layoutAttackPathGraph(model, "LR");
    const at = (id: string) => layout.positions.get(id)!;
    expect(at("helper").y).toBe(at("server").y);
    expect(at("helper").x).toBeGreaterThan(at("server").x);
    expect(at("lib").x).toBe(at("gateway").x);
    expect(at("lib").y).toBeGreaterThan(at("gateway").y);
  });

  it("reads the selected path left to right in hop order even when it visits identity before an agent", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    expect(model.nodes.find(node => node.id === "user:contractor")?.semanticLayer).toBe("user");
    const x = ["user:contractor", "sa:jit", "role:admin", "agent:copilot", "server:github", "pkg:next", "cve:next"].map(id => layout.positions.get(id)!.x);
    expect(x).toEqual([...x].sort((a, b) => a - b));
    expect(new Set(x).size).toBe(x.length);
  });

  it("fans branches out vertically from the shared node instead of extending the row", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const shared = layout.positions.get("agent:copilot")!;
    const branch = layout.positions.get("server:filesystem")!;
    const onPath = layout.positions.get("server:github")!;
    expect(branch.x).toBe(onPath.x);
    expect(branch.y).not.toBe(onPath.y);
    expect(branch.x).toBeGreaterThan(shared.x);
    const rects = [...layout.positions.values()];
    for (let i = 0; i < rects.length; i += 1) {
      for (let j = i + 1; j < rects.length; j += 1) {
        const a = rects[i]!, b = rects[j]!;
        const overlap = a.x < b.x + layout.nodeWidth && b.x < a.x + layout.nodeWidth && a.y < b.y + layout.nodeHeight && b.y < a.y + layout.nodeHeight;
        expect(overlap).toBe(false);
      }
    }
  });

  it("keeps a straight desktop row and a straight phone column", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const spineY = new Set(model.pathNodeIds.map(id => layout.positions.get(id)!.y));
    expect(spineY.size).toBe(1);
    const row = [...spineY][0]!;
    for (const node of model.nodes.filter(item => item.role === "branch")) {
      expect(layout.positions.get(node.id)!.y).not.toBe(row);
    }
    const vertical = layoutAttackPathGraph(model, "TB");
    expect(vertical.direction).toBe("TB");
    expect(new Set(model.pathNodeIds.map(id => vertical.positions.get(id)!.x)).size).toBe(1);
  });

  it("keeps clear column and branch-row spacing", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "LR");
    const x = model.pathNodeIds.map(id => layout.positions.get(id)!.x).sort((a, b) => a - b);
    for (let index = 1; index < x.length; index += 1) {
      // A card plus a 16px gap: ~112px of link between neighbouring 56px glyphs.
      expect(x[index]! - x[index - 1]!).toBeGreaterThanOrEqual(168);

    }
    const rowGap = Math.abs(layout.positions.get("server:filesystem")!.y - layout.positions.get("server:github")!.y);
    // Context may occupy several lanes; each lane leaves room for the two-line caption.
    expect(rowGap).toBeGreaterThanOrEqual(160);
    expect(rowGap % 168).toBe(0);
  });

  it("keeps the phone spine in the supplied hop order", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const layout = layoutAttackPathGraph(model, "TB");
    const y = model.pathNodeIds.map(id => layout.positions.get(id)!.y);
    expect(y).toEqual([...y].sort((a, b) => a - b));
    expect(layout.direction).toBe("TB");
    expect(new Set(y).size).toBe(model.pathNodeIds.length);
  });

  it("gives a phone a scrollable canvas at readable zoom", () => {
    const { graph, selected } = branchingFixture();
    const layout = layoutAttackPathGraph(buildAttackPathGraphModel(graph, selected), "TB");
    const zoom = narrowFitZoom(layout, 358);
    expect(zoom).toBeGreaterThanOrEqual(0.7);
    expect(zoom).toBeLessThanOrEqual(1);
    const height = attackPathCanvasHeight(layout, true, 358);
    expect(height).toBeGreaterThanOrEqual(Math.round(layout.height * zoom));
    expect(attackPathCanvasWidth(layout, true, 358)).toBe(358);
  });

  it("sizes the canvas to the laid-out graph within bounds", () => {
    const short = layoutAttackPathGraph(buildAttackPathGraphModel(fanOutFixture(0).graph, fanOutFixture(0).selected), "LR");
    expect(attackPathCanvasHeight(short, false)).toBeLessThanOrEqual(ATTACK_PATH_CANVAS_BOUNDS.min + 40);
    const { graph, selected } = branchingFixture();
    const branched = layoutAttackPathGraph(buildAttackPathGraphModel(graph, selected), "LR");
    // A narrower canvas fits a smaller zoom, so it reserves less height, never empty bands.
    expect(attackPathCanvasHeight(branched, false, 800)).toBeLessThanOrEqual(attackPathCanvasHeight(branched, false, 1600));
    const height = attackPathCanvasHeight(branched, false);
    expect(height).toBeGreaterThan(ATTACK_PATH_CANVAS_BOUNDS.min);
    expect(height).toBeLessThanOrEqual(ATTACK_PATH_CANVAS_BOUNDS.max);
    const tall = layoutAttackPathGraph(buildAttackPathGraphModel(fanOutFixture(40).graph, fanOutFixture(40).selected, { collapseThreshold: 100 }), "LR");
    expect(attackPathCanvasHeight(tall, false)).toBe(ATTACK_PATH_CANVAS_BOUNDS.max);
  });

  it("keeps context off the selected spine in both orientations", () => {
    for (const fixture of [branchingFixture(), demoFixture("headline"), demoFixture("runbook"), fanOutFixture(5)]) {
      const model = buildAttackPathGraphModel(fixture.graph, fixture.selected, { collapseThreshold: 100 });
      const branches = model.nodes.filter(item => item.role === "branch");
      expect(branches.length).toBeGreaterThan(0);
      const row = layoutAttackPathGraph(model, "LR");
      const spineY = row.positions.get(model.pathNodeIds[0]!)!.y;
      for (const branch of branches) expect(row.positions.get(branch.id)!.y, branch.id).not.toBe(spineY);
      const column = layoutAttackPathGraph(model, "TB");
      const spineX = column.positions.get(model.pathNodeIds[0]!)!.x;
      for (const branch of branches) expect(column.positions.get(branch.id)!.x, branch.id).toBeGreaterThan(spineX);
    }
  });

  it("keeps every node of a wide phone graph on the canvas at a legible zoom, scrolling instead of hiding", () => {
    const { graph, selected } = fanOutFixture(5);
    const layout = layoutAttackPathGraph(buildAttackPathGraphModel(graph, selected, { collapseThreshold: 100 }), "TB");
    const width = attackPathCanvasWidth(layout, true, 358);
    expect(width).toBe(358);
    const height = attackPathCanvasHeight(layout, true, width);
    const viewport = attackPathViewport(layout, selected.hops, { width, height }, NARROW_MIN_ZOOM);
    expect(viewport.zoom).toBeGreaterThanOrEqual(NARROW_MIN_ZOOM);
    expect(viewport.hiddenNodeIds).toEqual([]);
    // Both frames keep their width; the phone page scrolls vertically.
    expect(attackPathCanvasWidth(layout, false, 900)).toBe(900);
    const small = layoutAttackPathGraph(buildAttackPathGraphModel(fanOutFixture(0).graph, fanOutFixture(0).selected), "TB");
    expect(attackPathCanvasWidth(small, true, 358)).toBe(358);
  });
});

it("opens the complete phone path as a vertical spine with adjacent context and no sideways canvas", () => {
  const { graph, selected } = branchingFixture();
  const model = buildAttackPathGraphModel(graph, selected);
  const layout = layoutAttackPathGraph(model, "TB");
  expect(layout.direction).toBe("TB");
  const spine = model.pathNodeIds.map(id => layout.positions.get(id)!);
  expect(new Set(spine.map(p => p.x)).size).toBe(1);
  expect(spine.map(p => p.y)).toEqual([...spine.map(p => p.y)].sort((a, b) => a - b));
  expect(layout.width).toBeLessThanOrEqual(336);
  expect(attackPathCanvasWidth(layout, true, 358)).toBe(358);
  const height = attackPathCanvasHeight(layout, true, 358);
  const viewport = attackPathViewport(layout, model.pathNodeIds, { width: 358, height }, NARROW_MIN_ZOOM);
  expect(viewport.hiddenNodeIds).toEqual([]);
  expect(viewport.zoom * 56).toBeGreaterThanOrEqual(48);
  const points = [...layout.positions.values()];
  for (let i = 0; i < points.length; i++) for (const b of points.slice(i + 1)) {
    const a = points[i]!;
    expect(a.x + layout.nodeWidth <= b.x || b.x + layout.nodeWidth <= a.x || a.y + layout.nodeHeight <= b.y || b.y + layout.nodeHeight <= a.y).toBe(true);
  }
});
