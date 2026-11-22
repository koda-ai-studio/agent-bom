import { describe, expect, it } from "vitest";

import { resolveSnapshotAttackPathCount } from "@/lib/graph-snapshot-metrics";

describe("resolveSnapshotAttackPathCount", () => {
  it("reads the backend retained total independently of bounded page size", () => {
    expect(
      resolveSnapshotAttackPathCount({
        pageTotal: 2_155,
        statsTotal: 2_155,
        returnedPaths: 75,
        retained_count: 2_155,
        assessed_count: 3_000,
        basis: "derived_graph_paths",
      }),
    ).toBe(2_155);
  });

  it("reports unavailable for legacy totals without the shared backend contract", () => {
    expect(
      resolveSnapshotAttackPathCount({
        pageTotal: null,
        statsTotal: 820,
        returnedPaths: 75,
      }),
    ).toBeNull();
    expect(
      resolveSnapshotAttackPathCount({
        pageTotal: null,
        statsTotal: null,
        returnedPaths: 18,
      }),
    ).toBeNull();
  });
});
