import { expect, it } from "vitest";
import { queryStaticNodeAggregates } from "@/lib/static-demo-node-aggregates.mjs";

const table = { scan_id: "scan", tenant_id: "default", snapshot_generation: null, missing_node_ids: [],
  aggregates: [{ node_id: "a", aggregate: { issue_count: 2 } }, { node_id: "b", aggregate: { issue_count: 1 } }] };

it("answers any requested hop list from the table of every node, reporting the rest missing", () => {
  const answer = queryStaticNodeAggregates(table, "/v1/graph/node-aggregates?scan_id=scan&snapshot_generation=g1&node_id=b&node_id=z&node_id=b");
  expect(answer.aggregates.map((row: { node_id: string }) => row.node_id)).toEqual(["b"]);
  expect(answer.missing_node_ids).toEqual(["z"]);
  expect(answer.scan_id).toBe("scan");
  expect(answer.snapshot_generation).toBe("g1");
});
