import { expect, it } from "vitest";
import { GRAPH_SEMANTIC_LAYER_META } from "@/lib/graph-schema.generated";
import { semanticColumns, SEMANTIC_LAYER_COLUMNS } from "@/lib/graph-semantic-columns";

it("reads every column from the backend schema, including estate scope", () => {
  for (const [layer, meta] of Object.entries(GRAPH_SEMANTIC_LAYER_META)) {
    expect(SEMANTIC_LAYER_COLUMNS[layer as keyof typeof SEMANTIC_LAYER_COLUMNS]).toBe(meta.column);
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
