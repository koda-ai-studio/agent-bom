import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { plan, reportTests, units } from "../scripts/e2e-shard-plan.mjs";

type Unit = { location: string; seconds: number };
type Bin = { seconds: number; locations: string[] };

describe("duration-balanced E2E shards", () => {
  it("assigns every location exactly once and keeps the longest shard near the mean", () => {
    const timings = JSON.parse(readFileSync(join(process.cwd(), "e2e", "shard-timings.json"), "utf8")) as Record<string, number>;
    const listed = Object.keys(timings).map(location => [location, null] as [string, null]);
    const bins: Bin[] = plan(units(listed, timings), 8);
    const assigned = bins.flatMap(bin => bin.locations);
    expect(new Set(assigned).size).toBe(assigned.length);
    expect(new Set(assigned)).toEqual(new Set(Object.keys(timings)));
    const total = Object.values(timings).reduce((sum, seconds) => sum + seconds, 0);
    const longestUnit = Math.max(...Object.values(timings));
    expect(Math.max(...bins.map(bin => bin.seconds))).toBeLessThanOrEqual(total / 8 + longestUnit);
  });

  it("weights a test with no recorded duration as the median, so new specs still land in a shard", () => {
    const result: Unit[] = units([["e2e/a.spec.ts:1", null], ["e2e/b.spec.ts:2", null], ["e2e/new.spec.ts:9", null]], {
      "e2e/a.spec.ts:1": 2,
      "e2e/b.spec.ts:2": 10,
    });
    expect(result.find(unit => unit.location === "e2e/new.spec.ts:9")?.seconds).toBe(10);
  });

  it("is deterministic for equal weights", () => {
    const list: Unit[] = ["e2e/c.spec.ts:1", "e2e/a.spec.ts:1", "e2e/b.spec.ts:1"].map(location => ({ location, seconds: 1 }));
    expect(plan(list, 2)).toEqual(plan([...list].reverse(), 2));
  });

  it("reads locations from a Playwright JSON report, including nested describe blocks", () => {
    const report = {
      suites: [
        {
          file: "graph.spec.ts",
          specs: [{ file: "graph.spec.ts", line: 4, tests: [{ results: [{ duration: 1500 }] }] }],
          suites: [{ specs: [{ file: "graph.spec.ts", line: 20, tests: [{ results: [] }] }] }],
        },
      ],
    };
    expect(reportTests(report)).toEqual([
      ["e2e/graph.spec.ts:4", 1.5],
      ["e2e/graph.spec.ts:20", null],
    ]);
  });
});
