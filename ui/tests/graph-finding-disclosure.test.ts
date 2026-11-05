import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { cloudFindingDisclosure } from "@/lib/graph-finding-disclosure";
const nodes: Node<LineageNodeData>[] = [
  { id: "owner", position: { x: 0, y: 0 }, data: { nodeType: "container", label: "app", readingGroup: "Applications" } },
  { id: "finding", position: { x: 600, y: 0 }, data: { nodeType: "misconfiguration", label: "WAF missing", readingFinding: true, readingOwner: "owner", severity: "high" } },
];
const edges: Edge[] = [{ id: "affects", source: "finding", target: "owner", data: { relationship: "affects", evidenceMode: "inferred" } }];
it("collapses only uniquely owned findings and preserves records, count and severity", () => {
  const result = cloudFindingDisclosure(nodes, edges, new Set(), () => {});
  expect(result.nodes.find(n => n.id === "finding")!.hidden).toBe(true);
  expect(result.nodes[0]!.data.readingFindings).toMatchObject({ count: 1, expanded: false, severity: "high" });
  expect(result.edges[0]).toMatchObject({ ...edges[0], hidden: true });
  expect(nodes[1]!.hidden).toBeUndefined();
});
it("expands original IDs and original directed evidence", () => {
  const result = cloudFindingDisclosure(nodes, edges, new Set(["owner"]), () => {});
  expect(result.nodes.every(n => !n.hidden)).toBe(true);
  expect(result.edges[0]).toMatchObject(edges[0]!);
  expect(result.edges[0]!.hidden).toBeFalsy();
});
it("does not count or reveal findings hidden by filters", () => {
  const result = cloudFindingDisclosure(nodes.map(n => n.id === "finding" ? { ...n, hidden: true } : n), edges, new Set(["owner"]), () => {});
  expect(result.nodes[0]!.data.readingFindings).toBeUndefined();
  expect(result.nodes[1]!.hidden).toBe(true);
});

it("keeps manual positions when the operator has a saved or edited layout", () => {
  const cloudNodes: Node<LineageNodeData>[] = [
    { id: "account", position: { x: 80, y: 80 }, data: { nodeType: "account", label: "account" } },
    { ...nodes[0]!, data: { ...nodes[0]!.data, attributes: { container_kind: "workload" } } },
    { id: "role", position: { x: 440, y: 180 }, data: { nodeType: "role", label: "identity" } },
    nodes[1]!,
  ];
  const cloudEdges = [...edges,
    { id: "contains", source: "account", target: "owner", data: { relationship: "contains" } },
    { id: "identity", source: "owner", target: "role", data: { relationship: "authenticates_as" } },
  ];
  const automatic = cloudFindingDisclosure(cloudNodes, cloudEdges, new Set(["owner"]), () => {});
  expect(automatic.nodes.map(n => n.position)).not.toEqual(cloudNodes.map(n => n.position));
  const result = cloudFindingDisclosure(cloudNodes, cloudEdges, new Set(["owner"]), () => {}, true);
  expect(result.nodes.map(n => n.position)).toEqual(cloudNodes.map(n => n.position));
});

it("offers a separate finding group with original findings available on expansion", () => {
  const collapsed = cloudFindingDisclosure(nodes, edges, new Set(), () => {});
  const group = collapsed.nodes.find(n => n.type === "findingGroupNode");
  expect(group?.data.label).toBe("Findings");
  expect(group?.data.readingFindings?.count).toBe(1);
  expect(group?.data.displayOnly).toBe(true);
  const expanded = cloudFindingDisclosure(nodes, edges, new Set(["owner"]), () => {});
  expect(expanded.nodes.some(n => n.type === "findingGroupNode")).toBe(false);
  expect(expanded.nodes.find(n => n.id === "finding")?.hidden).toBe(false);
});

it("keeps finding disclosure available when an asset uses the display ID prefix", () => {
  const collision = { ...nodes[0]!, id: "display:findings:owner" };
  const result = cloudFindingDisclosure([...nodes, collision], edges, new Set(), () => {});
  expect(result.nodes.filter(n => n.type === "findingGroupNode")).toHaveLength(1);
  expect(new Set(result.nodes.map(n => n.id)).size).toBe(result.nodes.length);
});
