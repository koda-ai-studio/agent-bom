import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphHierarchyLayout } from "@/lib/graph-hierarchy-layout";
import { readableGraphEdges } from "@/lib/graph-utils";
import { declutterRelationshipLabels } from "@/lib/graph-label-declutter";
import { cloudHierarchyLayout } from "@/lib/graph-cloud-hierarchy";

const node = (id: string, nodeType: LineageNodeData["nodeType"]): Node<LineageNodeData> => ({
  id, type: "containerNode", position: { x: 0, y: 0 },
  data: { label: id, nodeType, ...(nodeType === "container" ? { attributes: { container_kind: "workload" } } : {}) },
});
const edge = (source: string, target: string, relationship: string): Edge => ({
  id: `${source}-${target}`, source, target, markerEnd: "arrow", data: { relationship, evidenceMode: "inferred" },
});
const nodes = [node("account", "account"), node("cluster", "cluster"), node("gateway", "apiGateway"),
  node("checkout", "container"), node("ledger", "container"), node("role", "role"), node("bucket", "dataStore"),
  node("cve", "vulnerability"), node("grant-finding", "misconfiguration")];
const edges = [edge("account", "cluster", "contains"), edge("account", "gateway", "contains"),
  edge("cluster", "checkout", "hosts"), edge("cluster", "ledger", "hosts"), edge("gateway", "checkout", "exposed_to"),
  edge("checkout", "role", "authenticates_as"), edge("role", "bucket", "has_permission"),
  edge("checkout", "cve", "vulnerable_to"), edge("grant-finding", "role", "affects")];

it("branches recorded findings from their assets while preserving access order", () => {
  const result = graphHierarchyLayout(nodes, edges);
  const byId = new Map(result.nodes.map(n => [n.id, n]));
  expect(byId.get("cluster")!.position.x).toBe(byId.get("gateway")!.position.x);
  expect(byId.get("checkout")!.position.x).toBe(byId.get("ledger")!.position.x);
  const chain = ["account", "cluster", "checkout", "role", "bucket"].map(id => byId.get(id)!.position.x);
  expect(chain.every((x, i) => i === 0 || x > chain[i - 1]!)).toBe(true);
  for (const [finding, owner] of [["cve", "checkout"], ["grant-finding", "role"]]) {
    expect(byId.get(finding!)!.position.x).toBeGreaterThan(byId.get(owner!)!.position.x);
    expect(byId.get(finding!)!.data.readingOwner).toBe(owner);
  }
  expect(byId.get("role")!.data.readingLabel).toBe("Permission role");
  expect(byId.get("checkout")!.data.readingLabel).toBe("Application");
  expect(result.edges.map(e => [e.source, e.target, e.markerEnd, e.data?.relationship])).toEqual(edges.map(e => [e.source, e.target, e.markerEnd, e.data?.relationship]));
  const captions = readableGraphEdges(result.edges);
  expect(captions.find(e => e.data?.relationship === "authenticates_as")!.ariaLabel).toMatch(/Authenticates As.*modeled/i);
  expect(captions.find(e => e.data?.relationship === "has_permission")!.ariaLabel).toMatch(/modeled/i);
});

it("is deterministic and preserves original records and modeled evidence", () => {
  const before = JSON.stringify({ nodes, edges });
  const a = graphHierarchyLayout(nodes, edges), b = graphHierarchyLayout([...nodes].reverse(), [...edges].reverse());
  expect(Object.fromEntries(a.nodes.map(n => [n.id, n.position]))).toEqual(Object.fromEntries(b.nodes.map(n => [n.id, n.position])));
  expect(JSON.stringify({ nodes, edges })).toBe(before);
  expect(a.edges.every(e => e.data?.evidenceMode === "inferred")).toBe(true);
});

it("does not assign a shared finding to an arbitrary owner", () => {
  expect(cloudHierarchyLayout(nodes, [...edges, edge("ledger", "cve", "vulnerable_to")])).toBeNull();
  expect(graphHierarchyLayout(nodes, [...edges, edge("ledger", "cve", "vulnerable_to")]).nodes).toHaveLength(nodes.length);
});

it("keeps unknown container subtypes, rollups and large estates on the general layout", () => {
  expect(cloudHierarchyLayout(nodes.map(n => n.id === "checkout" ? { ...n, data: { ...n.data, attributes: {} } } : n), edges)).toBeNull();
  expect(cloudHierarchyLayout(nodes.map(n => n.id === "role" ? { ...n, type: "clusterPillNode" } : n), edges)).toBeNull();
  expect(cloudHierarchyLayout([...nodes, ...Array.from({ length: 20 }, (_, i) => node(`extra-${i}`, "role"))], edges)).toBeNull();
});

it("reserves full captions and separates every node without dropping disconnected inventory", () => {
  const result = graphHierarchyLayout([...nodes, node("unlinked", "dataStore")], edges);
  expect(result.nodes).toHaveLength(nodes.length + 1);
  for (const a of result.nodes) for (const b of result.nodes) {
    if (a.id !== b.id && Math.abs(a.position.x - b.position.x) < 340) {
      expect(Math.abs(a.position.y - b.position.y)).toBeGreaterThanOrEqual(324);
    }
  }
});

it("explains each connection and separates findings from infrastructure entities", () => {
  const result = graphHierarchyLayout(nodes, edges);
  const displayed = declutterRelationshipLabels(readableGraphEdges(result.edges));
  expect(displayed.every(edge => edge.data?.quietLabel && edge.ariaLabel?.includes("relationship from"))).toBe(true);
  expect(displayed.some(edge => String(edge.label).includes("×"))).toBe(false);
  expect(result.nodes.find(node => node.id === "grant-finding")!.data.readingFinding).toBe(true);
  expect(result.edges.find(edge => edge.data?.relationship === "authenticates_as")!.label).toContain("Uses role");
});


it("anchors containment counts to their source asset and keeps access links explicit", () => {
  const result = graphHierarchyLayout(nodes, edges);
  const cluster = result.nodes.find(n => n.id === "cluster")!;
  expect(cluster.data.readingConnections).toEqual([{ relationship: "hosts", label: "2 applications", targets: ["checkout", "ledger"] }]);
  expect(result.nodes.find(n => n.id === "account")!.data.readingConnections).toEqual([{ relationship: "contains", label: "2 resources", targets: ["cluster", "gateway"] }]);
  expect(result.edges.filter(e => e.data?.relationship === "hosts").every(e => e.data?.quietLabel)).toBe(true);
  expect(result.nodes.find(n => n.id === "role")!.data.readingGroup).toBe("Identities");
  expect(result.nodes.find(n => n.id === "cve")!.data.readingOwner).toBe("checkout");
  expect(result.nodes.map(n => n.id)).toEqual(nodes.map(n => n.id));
});


it("distinguishes identity kinds without inventing role semantics or hidden inventory counts", () => {
  for (const kind of ["serviceAccount", "managedIdentity", "servicePrincipal"] as const) {
    const result = cloudHierarchyLayout(nodes.map(n => n.id === "role" ? { ...n, data: { ...n.data, nodeType: kind } } : n), edges)!;
    expect(result.nodes.find(n => n.id === "role")!.data.readingGroup).toBe("Identities");
    expect(result.edges.find(e => e.data?.relationship === "authenticates_as")!.label).toContain("Uses identity");
    expect(result.nodes.find(n => n.id === "role")!.data.readingLabel).not.toBe("Permission role");
  }
  const hidden = cloudHierarchyLayout(nodes.map(n => n.id === "ledger" ? { ...n, hidden: true } : n), edges)!;
  expect(hidden.nodes.find(n => n.id === "cluster")!.data.readingConnections).toEqual([]);
  const duplicates = cloudHierarchyLayout(nodes, [...edges, { ...edges[2]!, id: "duplicate-host-evidence" }])!;
  expect(duplicates.nodes.find(n => n.id === "cluster")!.data.readingConnections?.[0]?.label).toBe("2 applications");
});


it("places assets by recorded parent depth, not by entity category", () => {
  const result = cloudHierarchyLayout(nodes, edges.filter(e => e.target !== "ledger").concat(edge("account", "ledger", "hosts")))!;
  const at = new Map(result.nodes.map(n => [n.id, n.position]));
  expect(at.get("ledger")!.x).toBeLessThan(at.get("checkout")!.x);
  expect(result.nodes.every(n => !n.style?.paddingTop)).toBe(true);
});

it("supports several uniquely owned findings without inventing ownership for shared findings", () => {
  const result = cloudHierarchyLayout([...nodes, node("cve-2", "vulnerability")], [...edges, edge("checkout", "cve-2", "vulnerable_to")]);
  expect(result).not.toBeNull();
  expect(result!.nodes.find(n => n.id === "cve-2")!.data.readingOwner).toBe("checkout");
});
