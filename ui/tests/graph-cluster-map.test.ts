import { describe, expect, it } from "vitest";

import {
  CLUSTER_MAP_ELEMENT_BUDGET,
  INITIAL_CLUSTER_MAP_STATE,
  clusterMapEligible,
  bundleHandles,
  bundleLabel,
  bundleTitle,
  clusterMapLayout,
  clusterMapParams,
  pageCluster,
  toggleClusterExpanded,
  type ClusterMapEdge,
  type ClusterMapNode,
} from "@/lib/graph-cluster-map";

const cluster = (key: string, tier: number, extra: Partial<ClusterMapNode> = {}): ClusterMapNode => ({
  id: `@group:${key}`, kind: "cluster", cluster_key: key, label: key, tier, member_count: 3, worst_severity: "none", risky: false, expanded: false, ...extra,
});
const member = (id: string, clusterKey: string, tier: number): ClusterMapNode => ({ id, kind: "member", cluster_id: `@group:${clusterKey}`, label: id, tier, severity: "none" });
const more = (clusterKey: string, tier: number, count: number): ClusterMapNode => ({ id: `@more:${clusterKey}`, kind: "more", cluster_id: `@group:${clusterKey}`, label: `+${count} more`, tier, count });
const edge = (source: string, target: string, count: number, rels: Array<[string, number]> = [["depends_on", count]]): ClusterMapEdge => ({
  id: `${source}->${target}`, source, target, count, risky: false, relationships: rels.map(([relationship, n]) => ({ relationship, count: n })),
});

describe("bundled edge labels", () => {
  it("names the relationship and the exact count", () => {
    expect(bundleLabel(edge("a", "b", 38))).toBe("Depends On ×38");
    expect(bundleLabel(edge("a", "b", 40, [["depends_on", 30], ["uses", 8], ["contains", 2]]))).toBe("Depends On ×30 +2 more");
    expect(bundleTitle(edge("a", "b", 40, [["depends_on", 30], ["uses", 10]]))).toBe("40 relationships: Depends On ×30, Uses ×10");
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

describe("tier-column layout", () => {
  const view = {
    nodes: [
      cluster("type:agent", 1, { risky: true }),
      cluster("type:server", 2),
      cluster("package:pypi", 3),
      cluster("package:npm", 3, { risky: true, expanded: true }),
      member("pkg:1", "package:npm", 3),
      member("pkg:2", "package:npm", 3),
      more("package:npm", 3, 5),
      cluster("type:credential", 5),
    ],
    edges: [edge("@group:type:agent", "@group:type:server", 3), edge("@group:type:server", "pkg:1", 1), edge("@group:type:server", "@more:package:npm", 5)],
  };

  it("draws tiers as columns in exposure order, risky groups first, members under their group", () => {
    const placed = clusterMapLayout(view, { narrow: false });
    const at = new Map(placed.map(item => [item.node.id, item]));
    // Reading order (column, then top to bottom) follows the tiers.
    const order = (id: string) => [at.get(id)!.x, at.get(id)!.y] as const;
    const before = (a: string, b: string) => order(a)[0] < order(b)[0] || (order(a)[0] === order(b)[0] && order(a)[1] < order(b)[1]);
    expect(before("@group:type:agent", "@group:type:server")).toBe(true);
    expect(before("@group:type:server", "@group:package:npm")).toBe(true);
    expect(before("@group:package:npm", "@group:type:credential")).toBe(true);
    // The risky npm group leads its column; its members and pager follow it, before pypi.
    const column = placed.filter(item => item.node.tier === 3).sort((a, b) => a.y - b.y).map(item => item.node.id);
    expect(column).toEqual(["@group:package:npm", "pkg:1", "pkg:2", "@more:package:npm", "@group:package:pypi"]);
    expect(at.get("pkg:1")!.x).toBeGreaterThan(at.get("@group:package:npm")!.x);
  });

  it("never overlaps two cards, wide or on a phone", () => {
    for (const narrow of [false, true]) {
      const placed = clusterMapLayout(view, { narrow });
      expect(placed).toHaveLength(view.nodes.length);
      for (let i = 0; i < placed.length; i++) for (let j = i + 1; j < placed.length; j++) {
        const a = placed[i]!, b = placed[j]!;
        const overlap = a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y;
        expect(overlap, `${a.node.id} / ${b.node.id}`).toBe(false);
      }
    }
  });

  it("packs a sparse estate into a landscape frame instead of one thin column per tier", () => {
    const tiers = Array.from({ length: 8 }, (_, tier) => cluster(`type:t${tier}`, tier));
    const placed = clusterMapLayout({ nodes: tiers, edges: [] }, { narrow: false });
    const columns = new Set(placed.map(item => item.x)).size;
    expect(columns).toBeGreaterThan(1);
    expect(columns).toBeLessThan(8);
    const width = Math.max(...placed.map(item => item.x + item.width)), height = Math.max(...placed.map(item => item.y + item.height));
    expect(width / height).toBeGreaterThan(0.9);
    expect(width / height).toBeLessThan(4);
  });

  it("routes bundles between facing sides", () => {
    const placed = clusterMapLayout(view, { narrow: false });
    const at = new Map(placed.map(item => [item.node.id, item]));
    const sameColumn = placed.find(item => item.node.id !== "pkg:1" && item.x === at.get("pkg:1")!.x - 16 && item.y < at.get("pkg:1")!.y);
    expect(bundleHandles(sameColumn, at.get("pkg:1"), false)).toEqual({ sourceHandle: "b", targetHandle: "t" });
    expect(bundleHandles(at.get("pkg:1"), sameColumn, false)).toEqual({ sourceHandle: "t", targetHandle: "b" });
    const left = { ...at.get("pkg:1")!, x: -1000 };
    expect(bundleHandles(left, at.get("pkg:1"), false)).toEqual({ sourceHandle: "r", targetHandle: "l" });
    expect(bundleHandles(at.get("pkg:1"), left, false)).toEqual({ sourceHandle: "l", targetHandle: "r" });
  });

  it("leads the full map only when the ungrouped map would exceed one frame's budget", () => {
    const base = { hasScan: true, groupingOff: false, unavailable: false, focusedSurface: false, scopeNavigation: false, previewing: false, elements: 242, webgl: false };
    expect(clusterMapEligible(base)).toBe(true);
    expect(clusterMapEligible({ ...base, elements: CLUSTER_MAP_ELEMENT_BUDGET })).toBe(false);
    expect(clusterMapEligible({ ...base, elements: 10, webgl: true })).toBe(true);
    for (const key of ["groupingOff", "unavailable", "focusedSurface", "scopeNavigation", "previewing"] as const) expect(clusterMapEligible({ ...base, [key]: true })).toBe(false);
    expect(clusterMapEligible({ ...base, hasScan: false })).toBe(false);
  });

  it("fits a phone's width with at most two cards per line", () => {
    const placed = clusterMapLayout(view, { narrow: true });
    const right = Math.max(...placed.map(item => item.x + item.width));
    expect(right).toBeLessThanOrEqual(360);
    const tierOf = (id: string) => placed.find(item => item.node.id === id)!.y;
    expect(tierOf("@group:type:agent")).toBeLessThan(tierOf("@group:type:server"));
  });
});
