import { describe, expect, it, vi } from "vitest";

import type { GraphRollupContainer } from "@/lib/api-types";
import { groupRollupByImage, priorityScopes, rankScopesByRisk, scopeRiskScore } from "@/lib/graph-rollup-risk";
import { resolveScopeAncestry } from "@/lib/graph-scope-ancestry";

const scope = (id: string, counts: { critical?: number; high?: number; exposed?: number; toxic?: number; descendants?: number }, extra: Partial<GraphRollupContainer> = {}): GraphRollupContainer => ({
  id, label: id, entity_type: "account", severity: "", is_container: true, has_children: true, direct_child_count: 3,
  aggregate: {
    descendant_count: counts.descendants ?? 100, by_type: {},
    severity_counts: { critical: counts.critical ?? 0, high: counts.high ?? 0, medium: 0, low: 0 },
    worst_severity: counts.critical ? "critical" : counts.high ? "high" : "none", worst_severity_rank: counts.critical ? 5 : 0,
    internet_exposed: Boolean(counts.exposed), toxic_combo: Boolean(counts.toxic), exposed_count: counts.exposed ?? 0, toxic_count: counts.toxic ?? 0,
  },
  ...extra,
});

describe("rankScopesByRisk", () => {
  it("puts contained critical risk before size", () => {
    const big = scope("northstar-001", { critical: 3, high: 27, exposed: 17, descendants: 488 });
    const risky = scope("100000000002", { critical: 17, high: 24, exposed: 7, descendants: 270 });
    const mid = scope("northstar-000", { critical: 15, high: 36, exposed: 9, descendants: 279 });
    expect(rankScopesByRisk([big, mid, risky]).map(item => item.id)).toEqual(["100000000002", "northstar-000", "northstar-001"]);
  });

  it("weighs a toxic combination above one exposed asset when criticals tie", () => {
    const exposed = scope("exposed", { critical: 2, exposed: 1 });
    const toxic = scope("toxic", { critical: 2, toxic: 1 });
    expect(rankScopesByRisk([exposed, toxic]).map(item => item.id)).toEqual(["toxic", "exposed"]);
  });

  it("ranks a leaf finding by its own severity", () => {
    const leaf = scope("CVE-1", {}, { has_children: false, is_container: false, severity: "critical", entity_type: "vulnerability" });
    expect(scopeRiskScore(leaf)).toBeGreaterThan(scopeRiskScore(scope("quiet", { high: 2 })));
  });
});

describe("priorityScopes", () => {
  it("keeps only scopes scoring at least half the top score, so the filter discriminates", () => {
    const items = [scope("a", { critical: 17 }), scope("b", { critical: 12 }), scope("c", { critical: 3, exposed: 17 }), scope("d", { high: 20, exposed: 5 })];
    expect(priorityScopes(items).map(item => item.id)).toEqual(["a", "b"]);
  });

  it("is empty when nothing carries risk", () => {
    expect(priorityScopes([scope("a", {}), scope("b", {})])).toEqual([]);
  });
});

describe("groupRollupByImage", () => {
  const pkg = (id: string, image: string | undefined, critical: number) =>
    scope(id, { critical, high: 1 }, { entity_type: "package", context: image ? { image, environment: "development" } : { environment: "development" } });

  it("groups packages under their image so a drill reads environment → image → package", () => {
    const items = [pkg("langchain", "pharmacy-gateway-05:2026.08.01", 1), pkg("pyyaml", "pharmacy-gateway-05:2026.08.01", 2), pkg("jinja", "care-gap-jobs-03:2026.08.07", 0),
      pkg("loose", undefined, 0), scope("gke-01", { high: 2 }, { entity_type: "cluster" })];
    const { rows, images } = groupRollupByImage(items);
    expect(images.get("image:pharmacy-gateway-05:2026.08.01")!.map(item => item.id)).toEqual(["langchain", "pyyaml"]);
    const group = rows.find(row => row.id === "image:pharmacy-gateway-05:2026.08.01")!;
    expect(group.entity_type).toBe("image");
    expect(group.aggregate.severity_counts.critical).toBe(3);
    expect(group.direct_child_count).toBe(2);
    expect(rows.map(row => row.id)).toEqual(expect.arrayContaining(["loose", "gke-01", "image:care-gap-jobs-03:2026.08.07"]));
    expect(rows.some(row => row.id === "langchain")).toBe(false);
  });

  it("leaves a level without image context unchanged", () => {
    const items = [scope("a", { critical: 1 }), scope("b", {})];
    expect(groupRollupByImage(items).rows).toBe(items);
  });
});

describe("resolveScopeAncestry", () => {
  it("walks containment parents to the root for a deep-linked scope", async () => {
    const parents: Record<string, { id: string; label: string } | null> = {
      "env:gcp:northstar-001:development": { id: "account:gcp:northstar-001", label: "northstar-001" },
      "account:gcp:northstar-001": { id: "org:enterprise:northstar-health-ai", label: "Northstar Health AI" },
      "org:enterprise:northstar-health-ai": null,
    };
    const labels: Record<string, string> = { "account:gcp:northstar-001": "northstar-001", "org:enterprise:northstar-health-ai": "Northstar Health AI" };
    const getGraphNode = vi.fn(async (id: string) => {
      const parent = parents[id];
      return { node: { id, label: labels[id] ?? id }, edges_in: parent ? [{ source: parent.id, target: id, relationship: "contains" }] : [], neighbors: parent ? [parent.id] : [] };
    });
    const crumbs = await resolveScopeAncestry(getGraphNode as never, "env:gcp:northstar-001:development", "scan");
    expect(crumbs).toEqual([
      { id: "org:enterprise:northstar-health-ai", label: "Northstar Health AI" },
      { id: "account:gcp:northstar-001", label: "northstar-001" },
    ]);
  });

  it("stops on a cycle or a failed read without inventing ancestors", async () => {
    const getGraphNode = vi.fn(async (id: string) => {
      if (id === "b") throw new Error("404");
      return { node: { id, label: id }, edges_in: [{ source: "b", target: id, relationship: "contains" }], neighbors: ["b"] };
    });
    // The parent is known by id; its unreadable detail ends the walk.
    expect(await resolveScopeAncestry(getGraphNode as never, "a", "scan")).toEqual([{ id: "b", label: "b" }]);
    const cyclic = vi.fn(async (id: string) => ({ node: { id, label: id.toUpperCase() }, edges_in: [{ source: id === "a" ? "b" : "a", target: id, relationship: "contains" }], neighbors: [] }));
    expect(await resolveScopeAncestry(cyclic as never, "a", "scan")).toEqual([{ id: "b", label: "B" }]);
  });
});
