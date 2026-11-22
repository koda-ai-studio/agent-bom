import { GRAPH_SEMANTIC_LAYER_META } from "@/lib/graph-schema.generated";
import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { investigationFlow, type InvestigationFlow } from "@/lib/graph-investigation-flow";

// Explicit API fields: node type is deliberately independent of its layout layer.
const n = (id: string, nodeType: LineageNodeData["nodeType"], semanticLayer: string, attributes = {}): Node<LineageNodeData> => ({
  id, type: "containerNode", position: { x: 0, y: 0 }, data: { label: id, nodeType, semanticLayer, attributes },
});
const e = (source: string, target: string, relationship: string): Edge => ({ id: `${source}-${target}`, source, target, data: { relationship } });
const nodes = [n("account", "account", "scope"), n("cluster", "cluster", "infra"), n("endpoint", "apiGateway", "api_gateway", { resource_id: "api-1" }),
  n("pod", "container", "app", { kubernetes_kind: "Pod" }), n("role", "role", "identity"), n("bucket", "dataStore", "asset"), n("cve", "vulnerability", "finding")];
const edges = [e("account", "cluster", "contains"), e("cluster", "pod", "contains"), e("endpoint", "pod", "exposed_to"), e("pod", "role", "assumes"), e("role", "bucket", "has_permission"), e("pod", "cve", "vulnerable_to")];
const pinned = (input: Node<LineageNodeData>[], ids: string[]) => input.map(node => ids.includes(node.id)
  ? { ...node, data: { ...node.data, semanticPathIndex: ids.indexOf(node.id) } } : node);
const at = (result: ReturnType<typeof investigationFlow>, id: string) => result.nodes.find(node => node.id === id)!.position;

it("preserves a server-ranked exposure spine and leaves ownership in context", () => {
  const result = investigationFlow(pinned(nodes, ["endpoint", "pod", "role", "bucket"]), edges, "exposure");
  expect(at(result, "endpoint").x).toBeLessThan(at(result, "pod").x);
  expect(at(result, "account").y).not.toBe(at(result, "pod").y);
  expect(result.primaryPath).toEqual(["endpoint", "pod", "role", "bucket"]);
  expect(result.edges.map(edge => [edge.id, edge.source, edge.target])).toEqual(edges.map(edge => [edge.id, edge.source, edge.target]));
});

it("renders Internet context only for the backend folded exposure verdict", () => {
  for (const [attributes, exposed] of [
    [{ internet_exposed: true }, true], [{ risk_context: { internet_exposed: true } }, true],
    [{ internet_exposed: true, risk_context: { internet_exposed: false } }, false],
    [{ network_reachability_assessment: { complete: true, decision: "allow", source_scope: "internet", target_id: "api-1", evidence_refs: ["receipt"] } }, false],
    [{ public_ip: "192.0.2.1" }, false], [{ internet_exposed: "true" }, false], [{}, false],
  ] as const) {
    const input = nodes.map(node => node.id === "endpoint" ? { ...node, data: { ...node.data, attributes } } : node);
    const result = investigationFlow(input, edges, "exposure");
    expect(result.nodes.filter(node => node.data.label === "Internet")).toHaveLength(exposed ? 1 : 0);
    if (exposed) expect(result.edges.find(edge => edge.data?.displayOnly)).toMatchObject({ target: "endpoint", data: { traversable: false } });
  }
});

it("uses the same backend columns for identity, vulnerability and inventory", () => {
  const results = (["identity", "vulnerability", "inventory"] as InvestigationFlow[]).map(flow => investigationFlow(nodes, edges, flow));
  for (const result of results) {
    expect(result.applied).toBe(true);
    expect(result.primaryPath).toEqual([]);
    expect(at(result, "role").x).toBeLessThan(at(result, "bucket").x);
    expect(at(result, "cve").x).toBe(at(result, "pod").x);
    expect(at(result, "cve").y).toBeGreaterThan(at(result, "pod").y);
    expect(result.nodes.map(node => node.position)).toEqual(results[0]!.nodes.map(node => node.position));
  }
});

it("keeps a finding shared with a hidden asset outside a single-owner group", () => {
  const hidden = { ...n("second", "container", "app"), hidden: true };
  const result = investigationFlow([...nodes, hidden], [...edges, e("second", "cve", "vulnerable_to")], "exposure");
  expect(result.nodes.find(node => node.id === "cve")?.data.readingOwner).toBeUndefined();
});

it("does not derive columns from recorded ownership depth", () => {
  const result = investigationFlow(nodes, edges, "inventory");
  expect(at(result, "account").x).toBe(GRAPH_SEMANTIC_LAYER_META.scope.column * 380);
  expect(at(result, "cluster").x).toBe(GRAPH_SEMANTIC_LAYER_META.infra.column * 380);
  expect(at(result, "pod").x).toBe(GRAPH_SEMANTIC_LAYER_META.app.column * 380);
  expect(new Set(result.nodes.map(node => `${node.position.x}:${node.position.y}`)).size).toBe(nodes.length);
});

it("keeps sibling workloads and their findings off the server-ranked spine", () => {
  const input = pinned([...nodes, n("sibling", "container", "app"), n("sibling-cve", "vulnerability", "finding")], ["endpoint", "pod", "role", "bucket"]);
  const result = investigationFlow(input, [...edges, e("cluster", "sibling", "hosts"), e("sibling", "sibling-cve", "vulnerable_to")], "exposure");
  expect(result.primaryPath).not.toContain("sibling");
  expect(result.primaryPath).not.toContain("sibling-cve");
  expect(at(result, "sibling").y).not.toBe(at(result, "pod").y);
  expect(at(result, "sibling-cve").y).toBeGreaterThan(at(result, "sibling").y);
  expect(at(result, "sibling").x).toBe(GRAPH_SEMANTIC_LAYER_META.app.column * 380);
});

it("applies the same semantic layout to a package correlation view", () => {
  const input = [n("image", "container", "app"), n("package", "package", "package"), n("finding", "vulnerability", "finding")];
  const links = [e("image", "package", "contains"), e("package", "finding", "vulnerable_to")];
  const result = investigationFlow(input, links, "auto");
  expect(result.applied).toBe(true);
  expect(new Set(result.nodes.map(node => node.position.x)).size).toBe(1);
  expect(at(result, "finding").y).toBeGreaterThan(at(result, "package").y);
  expect(result.edges.map(edge => edge.id)).toEqual(links.map(edge => edge.id));
});

it("keeps semantic geometry unchanged on narrow screens for readable panning", () => {
  const desktop = investigationFlow(nodes, edges, "exposure");
  const mobile = investigationFlow(nodes, edges, "exposure", true);
  expect(mobile.nodes.map(node => node.position)).toEqual(desktop.nodes.map(node => node.position));
  expect(mobile.nodes.every(node => node.data.renderBand === "detail")).toBe(true);
});

it("gives successive server-ranked hops in the same semantic layer separate columns", () => {
  const input = pinned([...nodes, n("service", "cloudResource", "api_gateway")], ["endpoint", "service", "pod"]);
  const links = edges.filter(edge => edge.id !== "endpoint-pod").concat(e("endpoint", "service", "exposed_to"), e("service", "pod", "exposed_to"));
  const result = investigationFlow(input, links, "exposure");
  expect(at(result, "endpoint").x).toBeLessThan(at(result, "service").x);
  expect(at(result, "service").x).toBeLessThan(at(result, "pod").x);
});

it("routes reverse semantic-column links from their facing context handles", () => {
  const result = investigationFlow(nodes, [...edges, e("bucket", "pod", "related")], "exposure");
  expect(result.edges.find(edge => edge.id === "bucket-pod")).toMatchObject({ sourceHandle: "context", targetHandle: "context" });
  expect(result.edges.find(edge => edge.id === "pod-role")).toMatchObject({ sourceHandle: null, targetHandle: null });
});

it("retains a server-ranked workload-to-server path as a straight spine", () => {
  const ids = ["endpoint", "host", "server", "role", "data"];
  const input = pinned([n("endpoint", "apiGateway", "api_gateway"), n("host", "cloudResource", "app"), n("server", "server", "mcp_server"), n("role", "role", "identity"), n("data", "dataStore", "asset")], ids);
  const links = [e("endpoint", "host", "exposed_to"), e("host", "server", "hosts"), e("server", "role", "authenticates_as"), e("role", "data", "has_permission")];
  const result = investigationFlow(input, links, "exposure");
  expect(ids.map(id => at(result, id).y)).toEqual(ids.map(() => 0));
  const xs = ids.map(id => at(result, id).x);
  expect(xs).toEqual([...xs].sort((a, b) => a - b));
  expect(new Set(xs).size).toBe(ids.length);
  expect(result.edges.map(edge => [edge.source, edge.target])).toEqual(links.map(edge => [edge.source, edge.target]));
});

it("does not invent a path for disconnected workloads", () => {
  const input = [n("endpoint", "apiGateway", "api_gateway"), n("target", "cloudResource", "app"), n("other", "cloudResource", "app"), n("server", "server", "mcp_server")];
  const result = investigationFlow(input, [e("endpoint", "target", "exposed_to"), e("other", "server", "hosts")], "exposure");
  expect(result.primaryPath).toEqual([]);
  expect(result.edges.every(edge => !edge.data?.pathEmphasis && !edge.data?.flowStep)).toBe(true);
});

it("keeps containment edges without moving parents out of their backend layer", () => {
  const result = investigationFlow(nodes, edges, "exposure");
  for (const node of nodes.slice(0, 4)) expect(at(result, node.id).x).toBe(GRAPH_SEMANTIC_LAYER_META[node.data.semanticLayer as keyof typeof GRAPH_SEMANTIC_LAYER_META].column * 380);
  expect(result.edges.filter(edge => edge.data?.relationship === "contains").map(edge => [edge.source, edge.target])).toEqual([["account", "cluster"], ["cluster", "pod"]]);
});
