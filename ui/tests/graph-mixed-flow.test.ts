import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { mixedEvidenceFlow } from "@/lib/graph-mixed-flow";
import { graphHierarchyLayout } from "@/lib/graph-hierarchy-layout";
import { cloudFindingDisclosure } from "@/lib/graph-finding-disclosure";
const node = (id: string, nodeType: LineageNodeData["nodeType"]): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType, semanticLayer: ({ apiGateway: "api_gateway", server: "mcp_server", role: "identity", dataStore: "asset", vulnerability: "finding" } as Record<string, string>)[nodeType],
  ...(["endpoint", "mcp", "identity", "data"].includes(id) ? { semanticPathIndex: ["endpoint", "mcp", "identity", "data"].indexOf(id) } : {}) } });
const nodes = [node("endpoint", "apiGateway"), node("mcp", "server"), node("identity", "role"), node("data", "dataStore"), node("CVE-2026-1000", "vulnerability"), node("CVE-2026-2000", "vulnerability")];
nodes[1]!.data.rollup = { id: "mcp", label: "mcp", entity_type: "server", semantic_layer: "mcp_server", severity: "high", is_container: true, has_children: true, direct_child_count: 2,
  aggregate: { descendant_count: 9, by_type: {}, severity_counts: { high: 9 }, worst_severity: "high", worst_severity_rank: 4,
    internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0, issue_count: 9 } };
const edge = (source: string, target: string, relationship: string): Edge => ({ id: `${source}:${target}`, source, target, data: { relationship, evidenceMode: "inferred" } });
const edges = [edge("endpoint", "mcp", "exposed_to"), edge("mcp", "identity", "authenticates_as"), edge("identity", "data", "has_permission"), edge("mcp", nodes[4]!.id, "vulnerable_to"), edge(nodes[5]!.id, "mcp", "affects")];
it("keeps the mixed endpoint-to-data chain level and groups only singly owned findings", () => {
  const result = mixedEvidenceFlow(nodes, edges)!;
  expect(result.nodes.every(n => n.data.evidenceFlow)).toBe(true);
  expect(new Set(result.nodes.slice(0, 4).map(n => n.position.y)).size).toBe(1);
  expect(result.nodes.slice(4).map(n => n.data.readingOwner)).toEqual(["mcp", "mcp"]);
  const collapsed = cloudFindingDisclosure(result.nodes, result.edges, new Set(), () => {});
  expect(collapsed.nodes.filter(n => !n.hidden && !n.data.displayOnly).map(n => n.id)).toEqual(nodes.slice(0,4).map(n => n.id));
  expect(collapsed.nodes.filter(n => n.type === "findingGroupNode")).toHaveLength(1);
  expect(collapsed.nodes[1]!.data.readingFindings).toMatchObject({ count: 9, expanded: false });
  const expanded = cloudFindingDisclosure(result.nodes, result.edges, new Set(["mcp"]), () => {});
  expect(expanded.nodes.filter(n => !n.hidden)).toHaveLength(6);
  expect(expanded.edges.map(e => [e.id,e.source,e.target,e.data?.relationship,e.data?.evidenceMode])).toEqual(edges.map(e => [e.id,e.source,e.target,e.data?.relationship,e.data?.evidenceMode]));
});
it("never hides a shared finding, creates an endpoint, or chooses an arbitrary affected owner", () => {
  const shared = [...edges, edge(nodes[4]!.id, "data", "affects")];
  const result = graphHierarchyLayout(nodes, shared);
  expect(result.nodes.find(n => n.id === nodes[4]!.id)!.data.readingOwner).toBeUndefined();
  expect(result.nodes.map(n => n.id)).toEqual(nodes.map(n => n.id));
  const reversed = graphHierarchyLayout([...nodes].reverse(), [...edges].reverse());
  expect(Object.fromEntries(reversed.nodes.map(n => [n.id,n.position]))).toEqual(Object.fromEntries(graphHierarchyLayout(nodes,edges).nodes.map(n => [n.id,n.position])));
});
