import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphHierarchyLayout } from "@/lib/graph-hierarchy-layout";
import { readableGraphEdges } from "@/lib/graph-utils";
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

it("separates hosting, applications, identities and data, with findings below their assets", () => {
  const result = graphHierarchyLayout(nodes, edges);
  const byId = new Map(result.nodes.map(n => [n.id, n]));
  expect(byId.get("cluster")!.position.x).toBe(byId.get("gateway")!.position.x);
  expect(byId.get("checkout")!.position.x).toBe(byId.get("ledger")!.position.x);
  const chain = ["account", "cluster", "checkout", "role", "bucket"].map(id => byId.get(id)!.position.x);
  expect(chain.every((x, i) => i === 0 || x > chain[i - 1]!)).toBe(true);
  for (const [finding, owner] of [["cve", "checkout"], ["grant-finding", "role"]]) {
    expect(byId.get(finding!)!.position.x).toBe(byId.get(owner!)!.position.x);
    expect(byId.get(finding!)!.position.y - byId.get(owner!)!.position.y).toBeGreaterThanOrEqual(324);
  }
  expect(byId.get("role")!.data.readingLabel).toBe("Identity · permissions role");
  expect(byId.get("checkout")!.data.readingLabel).toBe("Application workload");
  expect(result.edges.map(e => [e.source, e.target, e.markerEnd, e.data?.relationship])).toEqual(edges.map(e => [e.source, e.target, e.markerEnd, e.data?.relationship]));
  const captions = readableGraphEdges(result.edges);
  expect(captions.find(e => e.data?.relationship === "authenticates_as")!.label).toBeTruthy();
  expect(captions.find(e => e.data?.relationship === "has_permission")!.label).toMatch(/modeled/i);
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
