import { SEMANTIC_COLUMN_GAP, SEMANTIC_ROW_GAP } from "@/lib/graph-semantic-layout";
import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphHierarchyLayout } from "@/lib/graph-hierarchy-layout";
import { readableGraphEdges } from "@/lib/graph-utils";
import { declutterRelationshipLabels } from "@/lib/graph-label-declutter";
import { cloudHierarchyLayout } from "@/lib/graph-cloud-hierarchy";

const node = (id: string, nodeType: LineageNodeData["nodeType"]): Node<LineageNodeData> => ({
  id, type: "containerNode", position: { x: 0, y: 0 },
  data: { label: id, nodeType, semanticLayer: ({ account: "scope", cluster: "infra", apiGateway: "api_gateway", container: "app", role: "identity", dataStore: "asset", vulnerability: "finding", misconfiguration: "finding" } as Record<string, string>)[nodeType], ...(nodeType === "container" ? { attributes: { container_kind: "workload" } } : {}) },
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

it("preserves recorded service names in the readable cloud view", () => {
  const services: Record<string, string> = { cluster: "eks", gateway: "api_gateway", role: "iam_role", bucket: "s3" };
  const recorded = nodes.map(n => services[n.id] ? { ...n, data: { ...n.data, attributes: { cloud_provider: "aws", service: services[n.id] } } } : n);
  const result = cloudHierarchyLayout(recorded, edges)!;
  const captions = Object.fromEntries(result.nodes.map(n => [n.id, n.data.readingLabel]));
  expect(captions).toMatchObject({ cluster: "Amazon EKS", gateway: "Amazon API Gateway", role: "AWS IAM role", bucket: "Amazon S3 bucket" });
  expect(captions.checkout).toBe("Workload");
  expect(captions.cve).toBe("CVE");
});

it("branches recorded findings from their assets while preserving access order", () => {
  const result = graphHierarchyLayout(nodes, edges);
  const byId = new Map(result.nodes.map(n => [n.id, n]));
  expect(byId.get("gateway")!.position.x).toBeLessThan(byId.get("cluster")!.position.x);
  // The gateway exposes checkout inside the app layer, so checkout reads one rank after its entry.
  expect(byId.get("checkout")!.position.x).toBeGreaterThan(byId.get("gateway")!.position.x);
  expect(byId.get("ledger")!.position.x).toBeLessThan(byId.get("checkout")!.position.x);
  // Backend layer order (scope, app, infra, identity, asset), with empty layers compressed.
  const chain = ["account", "checkout", "cluster", "role", "bucket"].map(id => byId.get(id)!.position.x);
  expect(chain).toEqual([...chain].sort((a, b) => a - b));
  expect(new Set(chain).size).toBe(chain.length);
  for (const [finding, owner] of [["cve", "checkout"], ["grant-finding", "role"]]) {
    expect(byId.get(finding!)!.position.x).toBeGreaterThan(byId.get(owner!)!.position.x);
    expect(byId.get(finding!)!.data.readingOwner).toBe(owner);
  }
  expect(byId.get("role")!.data.readingLabel).toBe("Role");
  expect(byId.get("checkout")!.data.readingLabel).toBe("Workload");
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
  expect(cloudHierarchyLayout(nodes, [...edges, edge("ledger", "cve", "vulnerable_to")]).nodes.find(n => n.id === "cve")!.data.readingOwner).toBeUndefined();
  expect(graphHierarchyLayout(nodes, [...edges, edge("ledger", "cve", "vulnerable_to")]).nodes).toHaveLength(nodes.length);
});

it("uses the shared grammar for unknown subtypes, grouped entries and large estates", () => {
  expect(cloudHierarchyLayout(nodes.map(n => n.id === "checkout" ? { ...n, data: { ...n.data, attributes: {} } } : n), edges).nodes).toHaveLength(nodes.length);
  expect(cloudHierarchyLayout(nodes.map(n => n.id === "role" ? { ...n, type: "clusterPillNode" } : n), edges).nodes).toHaveLength(nodes.length);
  expect(cloudHierarchyLayout([...nodes, ...Array.from({ length: 20 }, (_, i) => node(`extra-${i}`, "role"))], edges).nodes).toHaveLength(nodes.length + 20);
});

it("reserves full captions and separates every node without dropping disconnected inventory", () => {
  const result = graphHierarchyLayout([...nodes, node("unlinked", "dataStore")], edges);
  expect(result.nodes).toHaveLength(nodes.length + 1);
  for (const [i, a] of result.nodes.entries()) for (const b of result.nodes.slice(i + 1)) {
    expect(Math.abs(a.position.x - b.position.x) >= SEMANTIC_COLUMN_GAP || Math.abs(a.position.y - b.position.y) >= SEMANTIC_ROW_GAP).toBe(true);
  }
});

it("explains each connection and separates findings from infrastructure entities", () => {
  const result = graphHierarchyLayout(nodes, edges);
  const displayed = declutterRelationshipLabels(readableGraphEdges(result.edges));
  expect(displayed.every(edge => edge.data?.quietLabel && edge.ariaLabel?.includes("relationship from"))).toBe(true);
  expect(displayed.some(edge => String(edge.label).includes("×"))).toBe(false);
  expect(result.nodes.find(node => node.id === "grant-finding")!.data.readingFinding).toBe(true);
  expect(result.edges.find(edge => edge.data?.relationship === "authenticates_as")!.data?.relationship).toBe("authenticates_as");
});


it("does not derive containment badges from the visible edge subset", () => {
  const result = graphHierarchyLayout(nodes, edges);
  const cluster = result.nodes.find(n => n.id === "cluster")!;
  expect(cluster.data.readingConnections).toBeUndefined();
  expect(result.nodes.find(n => n.id === "account")!.data.readingConnections).toBeUndefined();
  expect(result.edges.filter(e => e.data?.relationship === "hosts").every(e => e.data?.quietLabel)).toBe(true);
  expect(result.nodes.find(n => n.id === "role")!.data.semanticLayer).toBe("identity");
  expect(result.nodes.find(n => n.id === "cve")!.data.readingOwner).toBe("checkout");
  expect(result.nodes.map(n => n.id)).toEqual(nodes.map(n => n.id));
});


it("distinguishes identity kinds without inventing role semantics or hidden inventory counts", () => {
  for (const kind of ["serviceAccount", "managedIdentity", "servicePrincipal"] as const) {
    const result = cloudHierarchyLayout(nodes.map(n => n.id === "role" ? { ...n, data: { ...n.data, nodeType: kind } } : n), edges)!;
    expect(result.nodes.find(n => n.id === "role")!.data.semanticLayer).toBe("identity");
    expect(result.edges.find(e => e.data?.relationship === "authenticates_as")!.data?.relationship).toBe("authenticates_as");
    expect(result.nodes.find(n => n.id === "role")!.data.readingLabel).not.toBe("Permission role");
  }
  const hidden = cloudHierarchyLayout(nodes.map(n => n.id === "ledger" ? { ...n, hidden: true } : n), edges)!;
  expect(hidden.nodes.find(n => n.id === "cluster")!.data.readingConnections).toBeUndefined();
  const duplicates = cloudHierarchyLayout(nodes, [...edges, { ...edges[2]!, id: "duplicate-host-evidence" }])!;
  expect(duplicates.nodes.find(n => n.id === "cluster")!.data.readingConnections).toBeUndefined();
});


it("retains backend layers when parent depth changes", () => {
  const result = cloudHierarchyLayout(nodes, edges.filter(e => e.target !== "ledger").concat(edge("account", "ledger", "hosts")))!;
  const at = new Map(result.nodes.map(n => [n.id, n.position]));
  // Ledger stays in its backend layer whatever its parent's depth; checkout follows the gateway that exposes it.
  expect(at.get("ledger")!.x).toBeLessThan(at.get("checkout")!.x);
  expect(at.get("ledger")!.x).toBe(at.get("gateway")!.x);
  expect(result.nodes.every(n => !n.style?.paddingTop)).toBe(true);
});

it("supports several uniquely owned findings without inventing ownership for shared findings", () => {
  const result = cloudHierarchyLayout([...nodes, node("cve-2", "vulnerability")], [...edges, edge("checkout", "cve-2", "vulnerable_to")]);
  expect(result).not.toBeNull();
  expect(result!.nodes.find(n => n.id === "cve-2")!.data.readingOwner).toBe("checkout");
});
