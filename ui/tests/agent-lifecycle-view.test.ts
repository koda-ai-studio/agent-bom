import { describe, expect, it } from "vitest";
import { lifecycleInventoryView } from "@/lib/agent-lifecycle-view";
import type { UnifiedGraphData } from "@/lib/graph-schema";

const nodes = [["a", "agent"], ["s1", "server"], ["s2", "server"], ["p", "package"], ["v", "vulnerability"], ["t", "tool"], ["c", "credential"]]
  .map(([id, entity_type]) => ({ id, entity_type, label: "same-label" }));
const edges = [["a", "s1", "uses"], ["a", "s2", "uses"], ["s1", "p", "depends_on"], ["s2", "p", "depends_on"],
  ["p", "v", "vulnerable_to"], ["s1", "t", "provides_tool"], ["s1", "c", "exposes_cred"], ["v", "t", "exploitable_via"],
  ["s2", "s1", "correlates_with"]].map(([source, target, relationship], index) => ({ id: `e${index}`, source, target, relationship,
    direction: "directed", evidence: { source: `receipt-${index}` } }));
const graph = { nodes, edges, attack_paths: [], interaction_risks: [], stats: { total_nodes: 7 } } as unknown as UnifiedGraphData;

describe("lifecycle inventory views", () => {
  it("starts with scoped server connections and retains original receipts", () => {
    const view = lifecycleInventoryView(graph, "servers", "s1");
    expect(view.nodes.map(n => n.id)).toEqual(["a", "s1", "s2"]);
    expect(view.edges).toEqual(graph.edges.slice(0, 2));
    expect(view.stats).toBe(graph.stats);
  });
  it("keeps shared package/advisory identity while selecting the exact server", () => {
    const view = lifecycleInventoryView(graph, "packages", "s2");
    expect(view.nodes.map(n => n.id)).toEqual(["a", "s2", "p", "v"]);
    expect(view.edges.map(e => e.id)).toEqual(["e1", "e3", "e4"]);
    expect(view.edges.every(e => graph.edges.includes(e))).toBe(true);
  });
  it("does not use correlation, reversed edges or derived exploitability as inventory links", () => {
    const input = { ...graph, edges: [...graph.edges, { ...graph.edges[2]!, id: "reverse", direction: "bidirectional" as const }] };
    const view = lifecycleInventoryView(input, "tools", "s1");
    expect(view.nodes.map(n => n.id)).toEqual(["a", "s1", "t", "c"]);
    expect(view.edges.map(e => e.id)).toEqual(["e0", "e5", "e6"]);
    expect(graph.nodes).toHaveLength(7);
    expect(graph.edges).toHaveLength(9);
  });
});
