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
    // Findings point into the repository, so they read on its left and their links join the facing sides.
    expect(preview?.edges.every(e => e.sourceHandle === null && e.targetHandle === null && e.data?.quietLabel)).toBe(true);
    expect(preview?.nodes.filter(n => n.id !== "repo").every(n => n.position.x < preview!.nodes.find(r => r.id === "repo")!.position.x)).toBe(true);
    // The root sits level with the middle neighbour.
    expect(preview?.nodes.find(n => n.id === "repo")?.position.y).toBe(preview?.nodes.find(n => n.id === "c")?.position.y);
    expect(preview?.nodes.every(n => n.data.rollup === undefined)).toBe(true);
    expect(buildScopePreview(items, edges, "orphan")).toBeNull();
  });
  it("reads what points into a scope on its left and what it points to on its right, centred on the scope's row", () => {
    const items = [item("agent", "agent"), item("role", "role"), item("policy", "policy"), item("portal", "container"), item("peer", "agent")];
    const edges: GraphRollupEdge[] = [
      { source: "role", target: "agent", count: 1, relationships: ["can_access"], directions: ["directed"] },
      { source: "policy", target: "agent", count: 1, relationships: ["governs"], directions: ["directed"] },
      { source: "agent", target: "portal", count: 1, relationships: ["hosted_on"], directions: ["directed"] },
      { source: "agent", target: "peer", count: 1, relationships: ["shares_server"], directions: ["bidirectional"] },
    ];
    const preview = buildScopePreview(items, edges, "agent")!;
    const at = (id: string) => preview.nodes.find(n => n.id === id)!.position;
    expect(preview.shownRelationships).toBe(4);
    expect(preview.rows).toBe(2);
    for (const id of ["role", "policy"]) expect(at(id).x).toBeLessThan(at("agent").x);
    // The two-way link takes the side with room: here the right, beside the scope's one outgoing link.
    for (const id of ["portal", "peer"]) expect(at(id).x).toBeGreaterThan(at("agent").x);
    expect(at("agent").y).toBe((at("role").y + at("policy").y) / 2);
    const handles = (source: string, target: string) => { const e = preview.edges.find(edge => edge.source === source && edge.target === target)!; return [e.sourceHandle, e.targetHandle]; };
    expect(handles("role", "agent")).toEqual([null, null]);
    expect(handles("agent", "portal")).toEqual([null, null]);
  });
  it("does not fabricate connectivity for missing endpoints, findings-only or unlinked inventories", () => {
    expect(buildScopePreview([item("repo", "application")], [])).toBeNull();
    expect(buildScopePreview([item("a"), item("b")], [{ source: "a", target: "b", count: 1, relationships: ["related_to"] }])).toBeNull();
    expect(buildScopePreview([item("repo", "application")], [{ source: "missing", target: "repo", count: 1, relationships: ["belongs_to"] }])).toBeNull();
  });
  it("shows different recorded finding families before repeating one MCP rule across tools", () => {
    const items = [item("root", "agent"), item("a", "misconfiguration", "MCP schema risk on browser_click: MCP-TOOL-07"),
      item("b", "misconfiguration", "MCP schema risk on browser_close: MCP-TOOL-07"),
      item("c", "misconfiguration", "Unpinned server version"), item("d", "misconfiguration", "Wildcard permissions")];
    const edges = items.slice(1).map(n => ({ source: n.id, target: "root", count: 1, relationships: ["affects"] }));
    expect(buildScopePreview(items, edges)?.nodes.map(n => n.id)).toEqual(["root", "a", "c", "d"]);
  });
});
