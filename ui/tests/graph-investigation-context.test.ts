import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphInvestigationContext, selectInvestigationContext, investigationRankEdges, restoreInvestigationEdges } from "@/lib/graph-investigation-context";

const node = (id: string, nodeType: LineageNodeData["nodeType"]): Node<LineageNodeData> => ({
  id, type: "containerNode", position: { x: 0, y: 0 }, data: { label: id, nodeType },
});
const edge = (source: string, target: string, relationship: string): Edge => ({
  id: `${source}:${relationship}:${target}`, source, target, data: { relationship },
});

describe("investigation context presentation", () => {
  const nodes = [node("role", "role"), node("agent", "agent"), node("peer", "agent"), node("github", "server"), node("filesystem", "server")];
  const edges = [edge("role", "agent", "can_access"), edge("agent", "github", "uses"), edge("agent", "filesystem", "uses"), edge("agent", "peer", "shares_server"), edge("peer", "filesystem", "uses")];

  it("anchors an agent investigation without making an incoming role its parent", () => {
    const result = graphInvestigationContext(nodes, edges, { rootId: "agent" });
    expect(result).not.toBeNull();
    expect(result!.anchorId).toBe("agent");
    expect(result!.nodes[0]!.id).toBe("agent");
    expect(result!.groups.find(group => group.id === "identity")?.nodeIds).toEqual(["role"]);
    expect(result!.edges).toEqual(edges);
    expect(new Set(result!.nodes.map(item => item.id))).toEqual(new Set(nodes.map(item => item.id)));
  });

  it("retains the anchor and the original access direction in an identity group", () => {
    const context = graphInvestigationContext(nodes, edges, { rootId: "agent" })!;
    const visible = selectInvestigationContext(context, "identity");
    expect(visible.nodes.map(item => item.id).sort()).toEqual(["agent", "role"]);
    expect(visible.edges).toEqual([edges[0]]);
    const ranked = investigationRankEdges(context, visible.edges);
    expect(ranked[0]!.source).toBe("agent");
    const restored = restoreInvestigationEdges(visible.edges, ranked);
    expect(restored[0]!.source).toBe("role");
    expect(restored[0]!.target).toBe("agent");
    expect(restored[0]!.data).toEqual(edges[0]!.data);
    expect(edges[0]!.source).toBe("role");
    expect(selectInvestigationContext(context, "all").edges).toEqual(edges);
  });

  it("does not reinterpret an identity investigation as an agent hierarchy", () => {
    expect(graphInvestigationContext(nodes, edges, { rootId: "role" })).toBeNull();
  });

  it("keeps dependency occurrences separate from workload and access context", () => {
    const entries = [node("manifest", "sourceFile"), node("image", "container"), node("deployment", "container"), node("pillow", "package"), node("cve", "vulnerability"), node("workload", "agent"), node("service-account", "serviceAccount"), node("records", "dataStore")];
    const links = [edge("manifest", "pillow", "contains"), edge("image", "pillow", "contains"), edge("deployment", "pillow", "contains"), edge("pillow", "cve", "vulnerable_to"), edge("deployment", "workload", "hosts"), edge("workload", "service-account", "acted_as"), edge("service-account", "records", "can_access")];
    const result = graphInvestigationContext(entries, links, { correlation: true });
    expect(result!.groups.find(group => group.id === "dependency")?.nodeIds.sort()).toEqual(["manifest", "image", "deployment", "pillow", "cve"].sort());
    expect(result!.groups.find(group => group.id === "workload")?.nodeIds.sort()).toEqual(["workload", "service-account", "records"].sort());
    expect(result!.edges).toEqual(links);
    expect(result!.nodes).toHaveLength(entries.length);
  });

  it("leaves large, unanchored and path views to their bounded navigation", () => {
    expect(graphInvestigationContext(nodes, edges, {})).toBeNull();
    expect(graphInvestigationContext(nodes, edges, { rootId: "missing" })).toBeNull();
    expect(graphInvestigationContext(nodes, edges, { rootId: "agent", pathSelected: true })).toBeNull();
    expect(graphInvestigationContext(Array.from({ length: 25 }, (_, i) => node(String(i), "agent")), [], { rootId: "0" })).toBeNull();
  });
});
