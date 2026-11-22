import { expect, it } from "vitest";
import { GRAPH_SEMANTIC_LAYER_META } from "@/lib/graph-schema.generated";
import { semanticColumns } from "@/lib/graph-semantic-columns";

it("reads every column from the backend schema, including estate scope", () => {
  for (const [layer, meta] of Object.entries(GRAPH_SEMANTIC_LAYER_META)) {
    expect(semanticColumns([{ id: layer, data: { semanticLayer: layer } }], []).get(layer)).toBe(meta.column);
  }
});

it("places an account scope before its infrastructure and keeps high columns distinct", () => {
  const nodes = [["account", "scope"], ["cluster", "infra"], ["gateway", "api_gateway"], ["agent", "orchestration"], ["data", "asset"]]
    .map(([id, semanticLayer]) => ({ id: id!, data: { semanticLayer } }));
  const columns = semanticColumns(nodes, []);
  expect(columns.get("account")).toBeLessThan(columns.get("cluster")!);
  expect(columns.get("account")).toBeLessThan(columns.get("gateway")!);
  expect(columns.get("agent")).toBeLessThan(columns.get("data")!);
  expect([...columns.values()].every(Number.isFinite)).toBe(true);
});

import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
it("orders same-layer scope containers by containment, independently of their ids", () => {
  const nodes = ["a-environment", "z-account", "y-organization"].map(id => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType: "account" as const, semanticLayer: "scope" } }));
  const edges = [{ id: "org-account", source: "y-organization", target: "z-account", data: { relationship: "hosts" } },
    { id: "account-env", source: "z-account", target: "a-environment", data: { relationship: "contains" } }];
  const placed = semanticGraphLayout(nodes, edges).nodes;
  const y = (id: string) => placed.find(node => node.id === id)!.position.y;
  // Containment inside one backend layer reads left to right: each child takes the next rank.
  const x = (id: string) => placed.find(node => node.id === id)!.position.x;
  expect(x("y-organization")).toBeLessThan(x("z-account"));
  expect(x("z-account")).toBeLessThan(x("a-environment"));
  expect(y("y-organization")).toBe(y("a-environment"));
});
