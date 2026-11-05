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
it("keeps identity, vulnerability and inventory flows distinct", () => {
  const positions = (["identity", "vulnerability", "inventory"] as InvestigationFlow[]).map(s => investigationFlow(nodes, edges, s).nodes.map(n => n.position));
  expect(positions[0]).not.toEqual(positions[1]);
  expect(positions[1]).not.toEqual(positions[2]);
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
    [...edges, e("cluster", "sibling", "hosts"), e("sibling", "sibling-cve", "vulnerable_to")], "exposure");
  const at = (id: string) => result.nodes.find(n => n.id === id)!.position;
  expect(at("sibling").y).toBeLessThan(at("pod").y);
  expect(at("sibling-cve").y).toBeLessThan(at("pod").y);
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
