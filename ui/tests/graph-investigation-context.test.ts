import { readableGraphNodeStyle } from "@/lib/graph-node-dimensions";
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
    expect(restoreInvestigationEdges(visible.edges, ranked, true)[0]).toMatchObject({ source: "role", target: "agent", sourceHandle: "context-up", targetHandle: "context", data: edges[0]!.data });
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
    expect(result!.groups.find(group => group.id === "dependency")?.nodeIds.sort()).toEqual(["manifest", "image", "pillow", "cve"].sort());
    expect(result!.groups.find(group => group.id === "workload")?.nodeIds.sort()).toEqual(["deployment", "workload", "service-account", "records"].sort());
    expect(result!.edges).toEqual(links);
    expect(result!.nodes).toHaveLength(entries.length);
  });

  it("leaves unanchored and path views to their bounded navigation", () => {
    expect(graphInvestigationContext(nodes, edges, {})).toBeNull();
    expect(graphInvestigationContext(nodes, edges, { rootId: "missing" })).toBeNull();
    expect(graphInvestigationContext(nodes, edges, { rootId: "agent", pathSelected: true })).toBeNull();
    expect(graphInvestigationContext(Array.from({ length: 25 }, (_, i) => node(String(i), "agent")), [], { rootId: "0" })).toBeNull();
  });
});

it("groups findings by their recorded asset instead of their category alone", () => {
  const nodes = [node("package", "package"), node("package-cve", "vulnerability"), node("workload", "agent"), node("cloud-policy", "misconfiguration"), node("server-cve", "vulnerability")];
  const edges = [edge("package", "package-cve", "vulnerable_to"), edge("cloud-policy", "workload", "affects"), edge("server-cve", "workload", "affects")];
  const context = graphInvestigationContext(nodes, edges, { correlation: true })!;
  expect(context.groups.find(group => group.id === "dependency")!.nodeIds).toEqual(["package", "package-cve"]);
  expect(context.groups.find(group => group.id === "workload")!.nodeIds).toEqual(["workload", "cloud-policy", "server-cve"]);
  expect(selectInvestigationContext(context, "all").edges).toEqual(edges);
});

it("keeps bounded investigation metadata readable after fitting all context", () => {
  const style = readableGraphNodeStyle(0.47, true) as Record<string, string>;
  expect(parseFloat(style["--graph-node-meta-size"]!) * 0.47).toBeGreaterThanOrEqual(11);
  const zoomedOut = readableGraphNodeStyle(0.42, true) as Record<string, string>;
  expect(parseFloat(zoomedOut["--graph-node-label-size"]!) * 0.42).toBeGreaterThanOrEqual(12);
});

describe("correlation evidence lanes", () => {
  it("separates evidence groups while preserving every recorded entity, edge and direction", async () => {
    const { layoutInvestigationLanes } = await import("@/lib/graph-investigation-context");
    const entries = [node("manifest", "sourceFile"), node("image", "container"), node("deployment", "container"), node("package", "package"), node("finding", "vulnerability"), node("service", "server"), node("workload", "agent"), node("identity", "serviceAccount"), node("records", "dataStore"), node("tool", "tool")];
    entries.forEach((n, i) => { n.position = { x: (i % 3) * 488, y: Math.floor(i / 3) * 400 }; });
    const links = [edge("manifest", "package", "contains"), edge("image", "package", "contains"), edge("deployment", "package", "contains"), edge("package", "finding", "vulnerable_to"), edge("deployment", "workload", "hosts"), edge("service", "workload", "exposes"), edge("workload", "identity", "authenticates_as"), edge("identity", "records", "can_access"), edge("workload", "tool", "invoked")];
    const context = graphInvestigationContext(entries, links, { correlation: true })!;
    const result = layoutInvestigationLanes(context, entries, links)!;
    expect(result.lanes.map(lane => lane.id)).toEqual(["workload", "dependency"]);
    expect(result.lanes[0]!.nodeIds).toContain("deployment");
    expect(result.lanes[1]!.nodeIds).not.toContain("deployment");
    expect(result.lanes[0]!.y + result.lanes[0]!.height).toBeLessThan(result.lanes[1]!.y);
    expect(result.nodes.map(n => n.id)).toEqual(entries.map(n => n.id));
    for (const lane of result.lanes) for (const id of lane.nodeIds) {
      const n = result.nodes.find(n => n.id === id)!;
      expect(n.position.y).toBeGreaterThanOrEqual(lane.y + 64);
      expect(n.position.y + Number(n.style?.minHeight)).toBeLessThanOrEqual(lane.y + lane.height);
      expect(n.data).toEqual(entries.find(item => item.id === id)!.data);
    }
    expect(result.edges.map(e => [e.id, e.source, e.target, e.data?.relationship])).toEqual(links.map(e => [e.id, e.source, e.target, e.data?.relationship]));
    expect(result.edges.every(e => e.data?.directionEmphasis === true && e.data?.quietLabel === false)).toBe(true);
    expect(links.every(e => e.data?.directionEmphasis === undefined)).toBe(true);
    expect(layoutInvestigationLanes(context, entries.filter(n => n.id === "workload"), [])).toBeNull();
  });
});
