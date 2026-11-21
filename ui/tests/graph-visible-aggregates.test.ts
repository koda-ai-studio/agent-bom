import { expect, it } from "vitest";
import { withGraphNodeAggregates, type GraphNodeAggregate } from "@/lib/graph-node-aggregates";
it("attaches only the backend aggregate to a visible canonical node", () => {
  const aggregate = { issue_count: 9, worst_severity: "critical", exposed_count: 2 } as GraphNodeAggregate["aggregate"];
  const record = { node_id: "asset", semantic_layer: "app", aggregate };
  const nodes = [{ id: "asset", position: { x: 0, y: 0 }, data: { label: "Asset", nodeType: "container" as const } },
    { id: "missing", position: { x: 0, y: 0 }, data: { label: "Missing", nodeType: "container" as const } }];
  const result = withGraphNodeAggregates(nodes, new Map([["asset", record]]));
  expect(result[0]!.data.findingAggregate).toBe(aggregate);
  expect(result[0]!.data.semanticLayer).toBe("app");
  expect(result[1]!.data.findingAggregate).toBeUndefined();
});
