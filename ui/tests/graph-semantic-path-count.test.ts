import { expect, it } from "vitest";
import { branchingFixture } from "./fixtures/attack-path-graph-fixture";
import { attackPathEvidenceGraph } from "@/lib/attack-path-graph-model";
import { buildFocusedGraphData } from "@/lib/security-graph-focus";
import { readAttackPathCounts, resolveSnapshotAttackPathCount } from "@/lib/graph-snapshot-metrics";

it("resolves the canvas count only from the shared backend object", () => {
  const input = { retained_count: 23, assessed_count: 71, basis: "derived_graph_paths", pageTotal: 999, statsTotal: 888, returnedPaths: 7 };
  expect(resolveSnapshotAttackPathCount(input)).toBe(23);
});

it("does not substitute legacy totals when the shared count is missing", () => {
  expect(resolveSnapshotAttackPathCount({ pageTotal: 999, statsTotal: 888, returnedPaths: 7 })).toBeNull();
});

it("reads the identical retained and assessed contract from stats and receipts", () => {
  const counts = { retained_count: 23, assessed_count: 71, basis: "derived_graph_paths" };
  expect(readAttackPathCounts(counts)).toEqual(counts);
  expect(readAttackPathCounts({ retained_count: 0, assessed_count: 9, basis: "derived_graph_paths" })?.retained_count).toBe(0);
});

it.each([undefined, { attack_path_count: 12 }, { retained_count: -1, assessed_count: 12, basis: "derived_graph_paths" },
  { retained_count: 7, assessed_count: 2, basis: "derived_graph_paths" }])("keeps missing or inconsistent counts unavailable", value => {
  expect(readAttackPathCounts(value)).toBeNull();
});

it.each([attackPathEvidenceGraph, buildFocusedGraphData])("preserves snapshot path totals when focusing one path", focus => {
  const { graph, selected } = branchingFixture();
  graph.stats.attack_path_count = 23;
  const result = focus(graph, selected)!;
  expect(result.attack_paths).toHaveLength(1);
  expect(result.stats.attack_path_count).toBe(23);
});
