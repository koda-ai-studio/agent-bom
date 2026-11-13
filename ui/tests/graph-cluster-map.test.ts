import { describe, expect, it } from "vitest";

import { clusterMapLayout, displayBundles, frameId, routeCards } from "@/lib/graph-cluster-layout";
import {
  CLUSTER_MAP_ELEMENT_BUDGET,
  INITIAL_CLUSTER_MAP_STATE,
  bundleLabel,
  bundleTitle,
  clusterMapEligible,
  clusterMapParams,
  pageCluster,
  severityWords,
  toggleClusterExpanded,
  type ClusterMapEdge,
  type ClusterMapNode,
} from "@/lib/graph-cluster-map";
import { boxesIntersect, pathCrossesBox, roundedPath, routeBundles, type Box } from "@/lib/graph-cluster-routes";

const cluster = (key: string, tier: number, extra: Partial<ClusterMapNode> = {}): ClusterMapNode => ({
  id: `@group:${key}`, kind: "cluster", cluster_key: key, label: key, tier, member_count: 3, worst_severity: "none", risky: false, expanded: false, ...extra,
});
const member = (id: string, clusterKey: string, tier: number): ClusterMapNode => ({ id, kind: "member", cluster_id: `@group:${clusterKey}`, label: id, tier, severity: "none" });
const more = (clusterKey: string, tier: number, count: number): ClusterMapNode => ({ id: `@more:${clusterKey}`, kind: "more", cluster_id: `@group:${clusterKey}`, label: `+${count} more`, tier, count });
const edge = (source: string, target: string, count: number, rels: Array<[string, number]> = [["depends_on", count]]): ClusterMapEdge => ({
  id: `${source}->${target}`, source, target, count, risky: false, relationships: rels.map(([relationship, n]) => ({ relationship, count: n })),
});

describe("bundled edge labels and card copy", () => {
  it("names the relationship and the exact count", () => {
    expect(bundleLabel(edge("a", "b", 38))).toBe("Depends On ×38");
    expect(bundleLabel(edge("a", "b", 40, [["depends_on", 30], ["uses", 8], ["contains", 2]]))).toBe("Depends On ×30 +2 more");
    expect(bundleTitle(edge("a", "b", 40, [["depends_on", 30], ["uses", 10]]))).toBe("40 relationships: Depends On ×30, Uses ×10");
  });

  it("states the worst severity as 'Worst: <word>'", () => {
    expect(severityWords({ worst_severity: "critical" })).toBe("Worst: critical");
    expect(severityWords({ worst_severity: "none" })).toBe("No critical or high findings");
  });
});

describe("expand, collapse and page state", () => {
  it("expanding adds the group, collapsing removes it and forgets its page", () => {
    const opened = toggleClusterExpanded(INITIAL_CLUSTER_MAP_STATE, "@group:package:npm");
    expect(opened.expanded).toEqual(["@group:package:npm"]);
    const paged = pageCluster(opened, "@group:package:npm", 8);
    expect(clusterMapParams("scan-1", paged).toString()).toBe("scan_id=scan-1&expand=%40group%3Apackage%3Anpm&page=8%3A%40group%3Apackage%3Anpm&member_limit=8");
    const closed = toggleClusterExpanded(paged, "@group:package:npm");
    expect(closed.expanded).toEqual([]);
    expect(closed.pages).toEqual({});
    expect(clusterMapParams(undefined, closed).toString()).toBe("member_limit=8");
  });

  it("collapsing the group a search opened clears the focus", () => {
    const focused = { ...INITIAL_CLUSTER_MAP_STATE, focus: "pkg:1" };
    expect(toggleClusterExpanded(focused, "@group:package:npm", "@group:package:npm").focus).toBeNull();
    expect(clusterMapParams(undefined, { ...focused, riskyOnly: true }).toString()).toBe("risky_only=true&focus=pkg%3A1&member_limit=8");
  });
});

describe("when the grouped map leads", () => {
  it("leads the full map only when the ungrouped map would exceed one frame's budget", () => {
    const base = { hasScan: true, groupingOff: false, unavailable: false, focusedSurface: false, scopeNavigation: false, previewing: false, elements: 242, webgl: false };
    expect(clusterMapEligible(base)).toBe(true);
    expect(clusterMapEligible({ ...base, elements: CLUSTER_MAP_ELEMENT_BUDGET })).toBe(false);
    expect(clusterMapEligible({ ...base, elements: 10, webgl: true })).toBe(true);
    for (const key of ["groupingOff", "unavailable", "focusedSurface", "scopeNavigation", "previewing"] as const) expect(clusterMapEligible({ ...base, [key]: true })).toBe(false);
    expect(clusterMapEligible({ ...base, hasScan: false })).toBe(false);
  });
});

/** A dense estate: every tier present, several groups per tier, bundles forwards, backwards, within a column and skipping columns. */
function denseView() {
  const tiers = [[0, ["type:provider", "type:account"]], [1, ["type:agent", "type:model", "type:application"]], [2, ["type:server", "type:tool"]],
    [3, ["package:npm", "package:pypi"]], [4, ["finding:critical", "finding:high", "finding:medium"]], [5, ["type:credential", "type:role"]],
    [6, ["cloud_resource:instance", "type:data_store"]]] as const;
  const nodes: ClusterMapNode[] = tiers.flatMap(([tier, keys]) => keys.map(key => cluster(key, tier, { risky: key.includes("critical") })));
  const ids = nodes.map(node => node.id);
  const edges: ClusterMapEdge[] = [];
  ids.forEach((source, i) => ids.forEach((target, j) => {
    if (i !== j && (i * 7 + j * 3) % 5 === 0) edges.push(edge(source, target, 1 + ((i + j) % 9) * 37, [["affects", 1 + ((i + j) % 9) * 37]]));
  }));
  return { nodes, edges };
}

function routed(view: { nodes: ClusterMapNode[]; edges: ClusterMapEdge[] }, narrow: boolean, active: string | null = null) {
  const layout = clusterMapLayout(view, { narrow });
  const bundles = displayBundles(view, active);
  const routes = routeBundles(routeCards(layout, active), bundles.map(b => ({ id: b.id, source: b.source, target: b.target, label: b.count > 1 ? bundleLabel(b) : null })), [...layout.cards, ...layout.frames]);
  return { layout, bundles, routes };
}

describe("one reading direction", () => {
  it("draws one column per tier in the order of reach, left to right", () => {
    const { layout } = routed(denseView(), false);
    const xByTier = new Map<number, number>();
    for (const card of layout.cards) xByTier.set(card.node.tier, card.x);
    const tiers = [...xByTier.keys()].sort((a, b) => a - b);
    for (let i = 1; i < tiers.length; i++) expect(xByTier.get(tiers[i]!)!).toBeGreaterThan(xByTier.get(tiers[i - 1]!)!);
    expect(new Set(layout.cards.map(card => card.column)).size).toBe(tiers.length);
  });

  it("routes every bundle left to right; a backward relationship keeps the route and moves the arrow", () => {
    const { routes, layout } = routed(denseView(), false);
    const cards = new Map(layout.cards.map(card => [card.node.id, card]));
    for (const route of routes) {
      const first = route.points[0]!, last = route.points.at(-1)!;
      expect(last.x).toBeGreaterThanOrEqual(first.x - 1e-6);
      for (let i = 0; i + 1 < route.points.length; i++) {
        const p = route.points[i]!, q = route.points[i + 1]!;
        expect(p.x === q.x || p.y === q.y).toBe(true);
      }
    }
    const backward = routes.find(route => route.id === "@group:finding:critical->@group:package:npm" || route.reversed);
    expect(backward?.reversed).toBe(true);
    expect(cards.size).toBeGreaterThan(0);
  });

  it("never routes a bundle through a card, wide or on a phone", () => {
    for (const narrow of [false, true]) {
      const { routes, layout } = routed(denseView(), narrow);
      expect(routes.length).toBeGreaterThan(10);
      const boxes = new Map(layout.cards.map(card => [card.node.id, card]));
      for (const route of routes) {
        const [source, target] = route.id.split("->");
        for (const card of layout.cards) {
          if (card.node.id === source || card.node.id === target) continue;
          expect(pathCrossesBox(route.points, card), `${route.id} through ${card.node.id}`).toBe(false);
        }
        expect(boxes.has(source!) && boxes.has(target!)).toBe(true);
      }
    }
  });

  it("shares one lane per source card in the gap after it", () => {
    const { routes } = routed(denseView(), false);
    const lanes = new Map<string, Set<number>>();
    for (const route of routes) {
      const from = route.reversed ? route.id.split("->")[1]! : route.id.split("->")[0]!;
      lanes.set(from, new Set([...(lanes.get(from) ?? []), route.points[1]!.x]));
    }
    for (const xs of lanes.values()) expect(xs.size).toBeLessThanOrEqual(2);
  });
});

describe("collision-free labels", () => {
  it("no two visible labels intersect, and no visible label intersects a card", () => {
    for (const narrow of [false, true]) {
      const { routes, layout } = routed(denseView(), narrow);
      const shown = routes.flatMap(route => route.label?.placed ? [route.label] : []);
      expect(shown.length).toBeGreaterThan(0);
      for (let i = 0; i < shown.length; i++) {
        for (let j = i + 1; j < shown.length; j++) expect(boxesIntersect(shown[i]!, shown[j]!)).toBe(false);
        for (const card of [...layout.cards, ...layout.frames] as Box[]) expect(boxesIntersect(shown[i]!, card)).toBe(false);
      }
    }
  });

  it("never draws a label for a single relationship; it stays for hover", () => {
    const view = { nodes: [cluster("type:agent", 1), cluster("type:server", 2)], edges: [edge("@group:type:agent", "@group:type:server", 1)] };
    const { routes } = routed(view, false);
    expect(routes[0]!.label).toBeNull();
  });

  it("draws rounded right-angle corners", () => {
    expect(roundedPath([{ x: 0, y: 0 }, { x: 40, y: 0 }, { x: 40, y: 40 }])).toBe("M 0 0 L 32 0 Q 40 0 40 8 L 40 40");
  });
});

describe("expanded groups", () => {
  const view = {
    nodes: [
      cluster("type:server", 2),
      cluster("package:npm", 3, { expanded: true, shown_member_count: 2 }),
      member("pkg:1", "package:npm", 3),
      member("pkg:2", "package:npm", 3),
      more("package:npm", 3, 5),
    ],
    edges: [edge("@group:type:server", "pkg:1", 1), edge("@group:type:server", "pkg:2", 1), edge("@group:type:server", "@more:package:npm", 5)],
  };

  it("draws one bundle to the group's frame carrying the whole count", () => {
    const { bundles, layout, routes } = routed(view, false);
    expect(bundles).toEqual([{ id: `@group:type:server->${frameId("@group:package:npm")}`, source: "@group:type:server", target: frameId("@group:package:npm"), count: 7, relationships: [{ relationship: "depends_on", count: 7 }], member: false }]);
    expect(layout.frames).toHaveLength(1);
    const frame = layout.frames[0]!;
    for (const card of layout.cards.filter(item => item.node.cluster_id === "@group:package:npm" || item.node.id === "@group:package:npm")) {
      expect(card.x >= frame.x && card.y >= frame.y && card.x + card.width <= frame.x + frame.width && card.y + card.height <= frame.y + frame.height).toBe(true);
    }
    expect(routes).toHaveLength(1);
  });

  it("shows a pointed-at member's own links and takes them out of the frame's count", () => {
    const bundles = displayBundles(view, "pkg:2");
    const total = bundles.reduce((sum, bundle) => sum + bundle.count, 0);
    expect(total).toBe(7);
    expect(bundles.find(bundle => bundle.target === "pkg:2")).toMatchObject({ count: 1, member: true });
    expect(bundles.find(bundle => bundle.target === frameId("@group:package:npm"))!.count).toBe(6);
  });
});
