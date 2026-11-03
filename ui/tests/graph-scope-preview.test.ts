import { describe, expect, it } from "vitest";
import { buildScopePreview } from "@/lib/graph-scope-preview";
import type { GraphRollupContainer, GraphRollupEdge } from "@/lib/api-types";

const item = (id: string, entity_type = "misconfiguration", label = id): GraphRollupContainer => ({
  id, label, entity_type, severity: "high", is_container: false, has_children: false, direct_child_count: 0,
  aggregate: { descendant_count: 0, by_type: {}, severity_counts: {}, worst_severity: "none", worst_severity_rank: 0,
    internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 },
});

describe("scope relationship preview", () => {
  it("shows named diverse findings around their recorded owner, with honest bounded totals", () => {
    const items = [item("repo", "application"), item("a", "misconfiguration", "Open port"),
      item("b", "misconfiguration", "Open port"), item("c", "misconfiguration", "Run as root"), item("d", "misconfiguration", "Secret in source"), item("orphan")];
    const edges: GraphRollupEdge[] = ["a", "b", "c", "d"].map(source => ({ source, target: "repo", count: 1, relationships: ["belongs_to"], directions: ["directed"] }));
    const preview = buildScopePreview(items, edges);
    expect(preview?.nodes.map(n => n.id)).toEqual(["repo", "a", "c", "d"]);
    expect(preview?.availableRelationships).toBe(4);
    expect(preview?.shownRelationships).toBe(3);
    expect(preview?.edges.map(e => [e.source, e.target])).toEqual([["a", "repo"], ["c", "repo"], ["d", "repo"]]);
    expect(preview?.edges.every(e => e.sourceHandle === "context" && e.targetHandle === "context" && e.data?.quietLabel)).toBe(true);
    expect(preview?.nodes.find(n => n.id === "repo")?.position.y).toBe(200);
    expect(preview?.nodes.every(n => n.data.rollup === undefined)).toBe(true);
    expect(buildScopePreview(items, edges, "orphan")).toBeNull();
  });
  it("does not fabricate connectivity for missing endpoints, findings-only or unlinked inventories", () => {
    expect(buildScopePreview([item("repo", "application")], [])).toBeNull();
    expect(buildScopePreview([item("a"), item("b")], [{ source: "a", target: "b", count: 1, relationships: ["related_to"] }])).toBeNull();
    expect(buildScopePreview([item("repo", "application")], [{ source: "missing", target: "repo", count: 1, relationships: ["belongs_to"] }])).toBeNull();
  });
});
