import type { Node } from "@xyflow/react";
import { expect, it } from "vitest";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";

const node = (id: string, attributes: Record<string, unknown>): Node<LineageNodeData> => ({
  id, position: { x: 0, y: 0 }, data: { label: id, nodeType: "container", semanticLayer: "infra", attributes },
});

it("draws exactly one Internet anchor for all folded true exposure verdicts", () => {
  const result = semanticGraphLayout([node("a", { internet_exposed: true }), node("b", { risk_context: { internet_exposed: true } })], []);
  const anchors = result.nodes.filter(n => n.data.displayOnly && n.data.label === "Internet");
  expect(anchors).toHaveLength(1);
  expect(result.edges.filter(e => e.source === anchors[0]!.id).map(e => e.target).sort()).toEqual(["a", "b"]);
  expect(result.edges.every(e => e.data?.displayOnly === true && e.data?.traversable === false)).toBe(true);
});

it("does not override folded false with a recorded true flag or guess from a public IP", () => {
  const result = semanticGraphLayout([node("a", { internet_exposed: true, risk_context: { internet_exposed: false } }),
    node("b", { public_ip: "203.0.113.1" }), node("c", { internet_exposed: "true" })], []);
  expect(result.nodes).toHaveLength(3);
  expect(result.edges).toHaveLength(0);
});

it("starts a selected exposed spine at the display anchor without duplicating it on relayout", () => {
  const nodes = [node("a", { internet_exposed: true }), node("b", {})];
  const result = semanticGraphLayout(nodes, [{ id: "ab", source: "a", target: "b" }], ["a", "b"]);
  const anchor = result.nodes.find(n => n.data.displayOnly)!;
  expect(anchor).toBeDefined();
  expect(anchor.position.x).toBeLessThan(result.nodes.find(n => n.id === "a")!.position.x);
  expect(new Set(result.nodes.map(n => n.position.y)).size).toBe(1);
  const repeated = semanticGraphLayout(result.nodes, result.edges, ["a", "b"]);
  expect(repeated.nodes).toHaveLength(3);
  expect(repeated.edges).toHaveLength(2);
});

import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { branchingFixture } from "./fixtures/attack-path-graph-fixture";
it("shows a display-only Internet anchor on a selected exposed path", () => {
  const { graph, selected } = branchingFixture();
  const source = graph.nodes.find(node => node.id === selected.hops[0])!;
  source.attributes = { ...source.attributes, risk_context: { internet_exposed: true } };
  const model = buildAttackPathGraphModel(graph, selected);
  expect(model.nodes.find(node => node.label === "Internet")?.displayOnly).toBe(true);
  expect(model.edges.find(edge => edge.source === "display:internet")?.onPath).toBe(false);
  expect(model.pathNodeIds[0]).toBe("display:internet");
});
