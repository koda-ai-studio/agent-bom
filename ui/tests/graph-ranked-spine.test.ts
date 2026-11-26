import { expect, it } from "vitest";
import { rankedVisibleSpine } from "@/lib/graph-ranked-spine";

const nodes = ["agent", "role", "data", "critical"].map(id => ({ id }));
const paths = [
  { hops: ["agent", "role", "data"], composite_risk: 7 },
  { hops: ["agent", "critical"], composite_risk: 9 },
];
const edges = [
  { source: "agent", target: "critical", data: { traversable: true } },
  { source: "agent", target: "role", data: { traversable: true } },
  { source: "role", target: "data", data: { traversable: true } },
];
it("preserves backend evidence ranking even when another path has higher composite risk", () => {
  expect(rankedVisibleSpine(nodes, edges, paths)).toEqual(["agent", "role", "data"]);
});
it("skips an incomplete page path without stitching the remaining hops", () => {
  expect(rankedVisibleSpine(nodes.filter(n => n.id !== "role"), edges, paths)).toEqual(["agent", "critical"]);
});
it("does not use blocked, reversed, or unknown traversal as an attack witness", () => {
  for (const change of [{ data: { traversable: false } }, { data: {} }, { source: "data", target: "role" }]) {
    expect(rankedVisibleSpine(nodes, [...edges.slice(0, 2), { ...edges[2]!, ...change }], paths)).toEqual(["agent", "critical"]);
  }
});
it("does not mutate server order and gives no partial path when none qualify", () => {
  expect(rankedVisibleSpine(nodes, [], paths)).toEqual([]);
  expect(paths[0]!.composite_risk).toBe(7);
});
it("does not substitute a different parallel relationship for a blocked ranked hop", () => {
  const links = [
    { source: "agent", target: "role", data: { relationship: "authenticates_as", traversable: false } },
    { source: "agent", target: "role", data: { relationship: "contains", traversable: true } },
  ];
  expect(rankedVisibleSpine(nodes, links, [{ hops: ["agent", "role"], edges: ["authenticates_as"], composite_risk: 9 }])).toEqual([]);
});
