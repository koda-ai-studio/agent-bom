import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { investigationFlow, type InvestigationFlow } from "@/lib/graph-investigation-flow";
const n = (id: string, nodeType: LineageNodeData["nodeType"], attributes = {}): Node<LineageNodeData> => ({ id, type: "containerNode", position: { x: 0, y: 0 }, data: { label: id, nodeType, attributes } });
const e = (source: string, target: string, relationship: string): Edge => ({ id: `${source}-${target}`, source, target, data: { relationship } });
const nodes = [n("account", "account"), n("cluster", "cluster"), n("endpoint", "apiGateway", { resource_id: "api-1" }), n("pod", "container", { kubernetes_kind: "Pod" }), n("role", "role"), n("bucket", "dataStore"), n("cve", "vulnerability")];
const edges = [e("account", "cluster", "contains"), e("cluster", "pod", "contains"), e("endpoint", "pod", "exposed_to"), e("pod", "role", "assumes"), e("role", "bucket", "has_permission"), e("pod", "cve", "vulnerable_to")];
const assessment = { complete: true, decision: "allow", source_scope: "internet", target_id: "api-1", evidence_refs: ["receipt-1"] };
it("starts exposure at the endpoint and puts ownership on a context branch", () => {
  const result = investigationFlow(nodes, edges, "exposure");
  const at = (id: string) => result.nodes.find(n => n.id === id)!.position;
  expect(at("endpoint").x).toBeLessThan(at("pod").x);
  expect(at("account").y).not.toBe(at("pod").y);
  expect(result.nodes.some(n => n.data.label === "Internet")).toBe(false);
  expect(result.edges.map(e => [e.id, e.source, e.target])).toEqual(edges.map(e => [e.id, e.source, e.target]));
});
it("renders Internet context only for a complete target-bound ingress assessment", () => {
  const inputs = nodes.map(n => n.id === "endpoint" ? { ...n, data: { ...n.data, attributes: { ...n.data.attributes, network_reachability_assessment: assessment } } } : n);
  const result = investigationFlow(inputs, edges, "exposure");
  expect(result.nodes.filter(n => n.data.label === "Internet")).toHaveLength(1);
  expect(result.edges.find(e => e.data?.displayOnly)).toMatchObject({ target: "endpoint", data: { traversable: false } });
  for (const invalid of [{ ...assessment, complete: false }, { ...assessment, decision: "deny" }, { ...assessment, target_id: "other" }, { ...assessment, source_scope: "outbound" }, { ...assessment, evidence_refs: [] }, { internet_exposed: true, public_ip: "8.8.8.8" }]) {
    const altered = inputs.map(n => n.id === "endpoint" ? { ...n, data: { ...n.data, attributes: { resource_id: "api-1", network_reachability_assessment: invalid } } } : n);
    expect(investigationFlow(altered, edges, "exposure").nodes.some(n => n.data.label === "Internet")).toBe(false);
  }
});
it("starts identity, vulnerability and inventory flows at their own subject and order their steps", () => {
  const flow = (scenario: InvestigationFlow) => {
    const result = investigationFlow(nodes, edges, scenario);
    return { result, at: (id: string) => result.nodes.find(n => n.id === id)!.position, origin: result.nodes.filter(n => n.position.x === 0 && n.position.y === 0).map(n => n.id) };
  };
  const identity = flow("identity"), vulnerability = flow("vulnerability"), inventory = flow("inventory");
  expect(identity.origin).toEqual(["role"]);
  expect(identity.at("role").x).toBeLessThan(identity.at("bucket").x);
  expect(vulnerability.origin).toEqual(["pod"]);
  expect(vulnerability.at("pod").x).toBeLessThan(vulnerability.at("cve").x);
  expect(vulnerability.at("cve").y).toBe(vulnerability.at("pod").y);
  expect(inventory.origin).toEqual(["account"]);
  expect(inventory.result.primaryPath.slice(0, 3)).toEqual(["account", "cluster", "pod"]);
});

it("keeps a finding shared with a hidden asset outside a single-owner group", () => {
  const hidden = { ...n("second", "container"), hidden: true };
  const result = investigationFlow([...nodes, hidden], [...edges, e("second", "cve", "vulnerable_to")], "exposure");
  expect(result.nodes.find(n => n.id === "cve")?.data.readingOwner).toBeUndefined();
});

it("uses recorded ownership depth in the explicit inventory flow", () => {
  const result = investigationFlow(nodes, edges, "inventory");
  const at = (id: string) => result.nodes.find(n => n.id === id)!.position;
  expect(at("account").x).toBeLessThan(at("cluster").x);
  expect(at("cluster").x).toBeLessThan(at("pod").x);
});

it("keeps sibling workloads and their findings on the deployment context branch", () => {
  const result = investigationFlow([...nodes, n("sibling", "container"), n("sibling-cve", "vulnerability")],
    [...edges, e("account", "endpoint", "contains"), e("cluster", "sibling", "hosts"), e("sibling", "sibling-cve", "vulnerable_to")], "exposure");
  const at = (id: string) => result.nodes.find(n => n.id === id)!.position;
  const primary = result.primaryPath;
  expect(primary).not.toContain("sibling");
  expect(primary).not.toContain("sibling-cve");
  expect(at("sibling").y).toBeGreaterThan(at("pod").y);
  expect(at("sibling-cve").y).toBeGreaterThan(at("pod").y);
  expect(at("sibling").x).toBeGreaterThan(at("cluster").x);
});

it("preserves the existing correlation layout when automatic flow has no cloud context", () => {
  const original = [n("image", "container"), n("package", "package"), n("finding", "vulnerability")];
  const links = [e("image", "package", "contains"), e("package", "finding", "vulnerable_to")];
  expect(investigationFlow(original, links, "auto").nodes).toBe(original);
});

it("reserves additional caption clearance on narrow screens", () => {
  const isolated = nodes.filter(n => ["endpoint", "pod", "cve"].includes(n.id));
  const links = edges.filter(e => isolated.some(n => n.id === e.source) && isolated.some(n => n.id === e.target));
  const desktop = investigationFlow(isolated, links, "exposure");
  const mobile = investigationFlow(isolated, links, "exposure", true);
  const gap = (result: typeof desktop) => Math.abs(result.nodes.find(n => n.id === "cve")!.position.y - result.nodes.find(n => n.id === "pod")!.position.y);
  expect(gap(mobile)).toBeGreaterThan(gap(desktop));
});

it("keeps an ingress and its routed Service in sequence before the pod", () => {
  const service = n("service", "cloudResource", { resource_type: "application_endpoint" });
  const links = edges.filter(e => e.id !== "endpoint-pod").concat(e("endpoint", "service", "exposed_to"), e("service", "pod", "exposed_to"));
  const result = investigationFlow([...nodes, service], links, "exposure");
  const x = (id: string) => result.nodes.find(n => n.id === id)!.position.x;
  expect(x("endpoint")).toBeLessThan(x("service"));
  expect(x("service")).toBeLessThan(x("pod"));
});
it("routes an upward context edge from the top of the node only when no card sits directly above it", () => {
  const flow = [n("endpoint", "apiGateway", { resource_id: "api-1" }), n("target", "cloudResource"), n("other", "cloudResource"), n("worker", "container"), n("parent", "cloudResource")];
  const links = [e("endpoint", "target", "exposed_to"), e("other", "worker", "contains"), e("parent", "other", "contains")];
  const result = investigationFlow(flow, links, "exposure");
  const handle = (id: string) => result.edges.find(edge => edge.id === id)?.sourceHandle;
  const at = (id: string) => result.nodes.find(n => n.id === id)!.position;
  const clearAbove = (id: string, target: string) => !result.nodes.some(node => node.id !== target && node.position.x === at(id).x && node.position.y < at(id).y && node.position.y >= at(target).y);
  for (const edge of result.edges.filter(edge => edge.data?.relationship === "contains" && at(edge.target).y < at(edge.source).y && at(edge.source).x <= at(edge.target).x)) {
    expect(handle(edge.id)).toBe(clearAbove(edge.source, edge.target) ? "context-up" : undefined);
  }
  const blocked = investigationFlow(nodes, edges, "exposure");
  const blockedAt = (id: string) => blocked.nodes.find(node => node.id === id)!.position;
  expect(blockedAt("cluster").y).toBeGreaterThan(blockedAt("pod").y);
  expect(blocked.edges.find(edge => edge.id === "cluster-pod")?.sourceHandle).toBeUndefined();
  expect(blocked.edges.find(edge => edge.id === "endpoint-pod")?.sourceHandle).toBeUndefined();
});
it("continues an exposure flow through a workload the exposed host runs", () => {
  const flow = [n("endpoint", "apiGateway", { resource_id: "api-1" }), n("host", "cloudResource"), n("server", "server"), n("role", "role"), n("data", "dataStore")];
  const links = [e("endpoint", "host", "exposed_to"), e("host", "server", "hosts"), e("server", "role", "authenticates_as"), e("role", "data", "has_permission")];
  const result = investigationFlow(flow, links, "exposure");
  const at = (id: string) => result.nodes.find(n => n.id === id)!.position;
  expect(["endpoint", "host", "server", "role", "data"].map(id => at(id).y)).toEqual([0, 0, 0, 0, 0]);
  const xs = ["endpoint", "host", "server", "role", "data"].map(id => at(id).x);
  expect(xs).toEqual([...xs].sort((a, b) => a - b));
  expect(new Set(xs).size).toBe(5);
  expect(result.edges.map(edge => [edge.source, edge.target])).toEqual(links.map(edge => [edge.source, edge.target]));
});
it("keeps a workload outside the entry flow when no exposed host reaches it", () => {
  const flow = [n("endpoint", "apiGateway", { resource_id: "api-1" }), n("target", "cloudResource"), n("other", "cloudResource"), n("server", "server")];
  const result = investigationFlow(flow, [e("endpoint", "target", "exposed_to"), e("other", "server", "hosts")], "exposure");
  const at = (id: string) => result.nodes.find(n => n.id === id)!.position;
  expect(at("server").y).not.toBe(at("target").y);
});
