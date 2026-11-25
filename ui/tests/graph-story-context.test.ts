import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { storyContext } from "@/lib/graph-story-context";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
const n = (id: string, nodeType: LineageNodeData["nodeType"], path?: number): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType, semanticPathIndex: path } });
const nodes = [n("display:internet", "environment", 0), n("entry", "apiGateway", 1), n("app", "container", 2), n("cve", "vulnerability", 3), n("role", "role"), n("data", "dataStore"), n("account", "account"), n("cluster", "cluster"), n("sibling", "container")];
const e = (source: string, target: string, relationship: string, traversable = true): Edge => ({ id: `${source}-${target}`, source, target, data: { relationship, traversable } });
const edges = [e("display:internet", "entry", "exposed_to"), e("entry", "app", "exposed_to"), e("app", "cve", "vulnerable_to"), e("app", "role", "authenticates_as"), e("role", "data", "has_permission"), e("account", "cluster", "contains", false), e("account", "entry", "contains", false), e("cluster", "app", "hosts", false), e("cluster", "sibling", "hosts", false)];
it("opens the recorded exposure and access story with supporting containment explicitly folded", () => {
  const result = storyContext(nodes, edges, false);
  expect(result.contextIds).toEqual(new Set(["account", "cluster", "sibling"]));
  expect(result.nodes.filter(n => !n.hidden).map(n => n.id)).toEqual(["display:internet", "entry", "app", "cve", "role", "data"]);
  expect(result.edges.filter(e => !e.hidden).map(e => e.id)).toEqual(edges.slice(0, 5).map(e => e.id));
  expect(result.edges.map(e => [e.id, e.source, e.target, e.data])).toEqual(edges.map(e => [e.id, e.source, e.target, e.data]));
  expect(nodes.every(n => !n.hidden)).toBe(true);
});
it("expanded context retains the account and its actual containment links, never a floating frame caption", () => {
  const restored = storyContext(nodes, edges, true);
  const result = semanticGraphLayout(restored.nodes, restored.edges);
  expect(result.nodes.find(n => n.id === "account")?.hidden).toBeFalsy();
  expect(result.nodes.some(n => n.type === "boundaryFrame")).toBe(false);
  expect(result.edges.find(e => e.id === "account-cluster")?.hidden).toBeFalsy();
  expect(result.edges.find(e => e.id === "account-entry")?.hidden).toBeFalsy();
});
it("does not fold a broken or nontraversable primary witness", () => {
  for (const links of [edges.filter(e => e.id !== "entry-app"), edges.map(e => e.id === "entry-app" ? { ...e, data: { ...e.data, traversable: false } } : e)]) {
    expect(storyContext(nodes, links, false).contextIds.size).toBe(0);
  }
});
it("does not infer access from type, reverse direction, or containment", () => {
  const result = storyContext(nodes, edges.filter(e => e.id !== "app-role").concat(e("role", "app", "authenticates_as")), false);
  expect(result.nodes.find(n => n.id === "role")?.hidden).toBe(true);
  expect(result.nodes.find(n => n.id === "data")?.hidden).toBe(true);
});


it("leaves large inventories and roll-up containers in their own overview", () => {
  const large = nodes.concat(Array.from({ length: 30 }, (_, i) => n(`extra:${i}`, "container")));
  expect(storyContext(large, edges, false).nodes).toBe(large);
  const rolled = nodes.map(node => node.id === "account" ? { ...node, data: { ...node.data, attributes: { rollup_is_container: true } } } : node);
  expect(storyContext(rolled, edges, false).nodes).toBe(rolled);
});

it("expansion preserves pre-existing filters and does not promote blocked access", () => {
  const filtered = nodes.map(node => node.id === "sibling" ? { ...node, hidden: true } : node);
  const links = edges.map(edge => edge.id === "app-role" ? { ...edge, data: { ...edge.data, traversable: false } } : edge);
  const result = storyContext(filtered, links, true);
  expect(result.nodes.find(node => node.id === "sibling")?.hidden).toBe(true);
  expect(result.edges.find(edge => edge.id === "app-role")?.data?.traversable).toBe(false);
});
