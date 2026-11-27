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

import { queryStaticScopeFindings } from "@/lib/static-demo-node-aggregates.mjs";

it("pages the selected server-derived scope and refuses missing scope evidence", () => {
  const scopes = { a: { node_id: "a", scan_id: "scan", total: 2, findings: [{ issue_key: "one" }, { issue_key: "two" }] },
    b: { node_id: "b", scan_id: "scan", total: 1, findings: [{ issue_key: "private-to-b" }] } };
  expect(queryStaticScopeFindings({ scopes }, "/v1/graph/scope-findings?node_id=a&offset=1&limit=1"))
    .toMatchObject({ node_id: "a", total: 2, findings: [{ issue_key: "two" }] });
  expect(() => queryStaticScopeFindings({ scopes }, "/v1/graph/scope-findings?node_id=missing")).toThrow("No finding evidence");
});
