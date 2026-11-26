import { expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { scopeStories, selectScopeStory } from "@/lib/graph-scope-stories";
const n = (id: string, nodeType: LineageNodeData["nodeType"]): Node<LineageNodeData> => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType } });
const e = (source: string, target: string, relationship: string): Edge => ({ id: `${source}-${target}`, source, target, data: { relationship, traversable: false } });
const nodes = [n("account", "account"), n("display:internet", "environment"), n("entry", "container"), n("finding", "vulnerability"), n("agent", "agent"), n("server", "server"), n("data", "dataStore")];
const edges = [e("account", "entry", "contains"), e("account", "agent", "contains"), e("display:internet", "entry", "exposed_to"), e("entry", "finding", "vulnerable_to"), e("agent", "server", "uses"), e("server", "data", "can_access")];
it("offers independent recorded flows instead of stacking unrelated chains", () => {
  const stories = scopeStories(nodes, edges)!;
  expect(stories.stories.map(s => s.label)).toEqual(["Internet exposure", "agent"]);
  const result = selectScopeStory(nodes, edges, stories, stories.stories[0]!.id);
  expect(result.nodes.filter(n => !n.hidden).map(n => n.id)).toEqual(["account", "display:internet", "entry", "finding"]);
  expect(result.edges.filter(e => !e.hidden).map(e => e.id)).toEqual(edges.slice(0, 1).concat(edges.slice(2, 4)).map(e => e.id));
  expect(result.edges.map(e => [e.id, e.source, e.target, e.data])).toEqual(edges.map(e => [e.id, e.source, e.target, e.data]));
});
it("drills into another flow with the same account context and no invented Internet link", () => {
  const stories = scopeStories(nodes, edges)!;
  const result = selectScopeStory(nodes, edges, stories, stories.stories[1]!.id);
  expect(result.nodes.filter(n => !n.hidden).map(n => n.id)).toEqual(["account", "agent", "server", "data"]);
  expect(result.edges.filter(e => !e.hidden).map(e => e.id)).toEqual(["account-agent", "agent-server", "server-data"]);
});
it("never splits real cross-links, bypasses filters, or infers permission from containment", () => {
  expect(scopeStories(nodes, [...edges, e("entry", "server", "uses")])).toBeNull();
  expect(scopeStories(nodes, edges.map(e => e.source === "account" ? { ...e, data: { relationship: "can_access" } } : e))).toBeNull();
  expect(scopeStories(nodes.map(n => n.id === "agent" ? { ...n, hidden: true } : n), edges)).toBeNull();
  expect(scopeStories([...nodes, ...Array.from({ length: 25 }, (_, i) => n(`extra:${i}`, "container"))], edges)).toBeNull();
  expect(scopeStories(nodes.map(n => n.id === "account" ? { ...n, data: { ...n.data, attributes: { rollup_is_container: true } } } : n), edges)).toBeNull();
});
