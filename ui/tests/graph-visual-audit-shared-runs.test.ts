import { describe, expect, it } from "vitest";

import { sharedRelationshipRuns } from "../scripts/graph-visual-audit.mjs";

const line = (points: Array<[number, number]>) => points.map(([x, y]) => ({ x, y }));

describe("relationship lines that share a run", () => {
  it("reports two relationship types drawn along one horizontal segment", () => {
    // Today's mesh capture: Can Access into Developer Copilot on the same row as its Uses lines.
    const shared = sharedRelationshipRuns([
      { id: "uses", relationship: "Uses", points: line([[578, 522], [740, 522], [740, 367], [915, 367]]) },
      { id: "access", relationship: "Can Access", points: line([[915, 680], [745, 680], [745, 522], [578, 522]]) },
    ]);
    expect(shared).toEqual([{ edges: ["uses", "access"], length: 162 }]);
  });

  it("allows one relationship type to bundle on a shared run", () => {
    expect(sharedRelationshipRuns([
      { id: "a", relationship: "Uses", points: line([[0, 0], [200, 0], [200, 100]]) },
      { id: "b", relationship: "Uses", points: line([[0, 0], [200, 0], [200, -100]]) },
    ])).toEqual([]);
  });

  it("accepts different types on parallel lanes a few pixels apart", () => {
    expect(sharedRelationshipRuns([
      { id: "uses", relationship: "Uses", points: line([[0, 515], [300, 515]]) },
      { id: "access", relationship: "Can Access", points: line([[0, 529], [300, 529]]) },
    ])).toEqual([]);
  });

  it("ignores a touch shorter than the minimum run", () => {
    expect(sharedRelationshipRuns([
      { id: "a", relationship: "Uses", points: line([[0, 0], [100, 0]]) },
      { id: "b", relationship: "Can Access", points: line([[96, 0], [200, 0]]) },
    ])).toEqual([]);
  });
});
