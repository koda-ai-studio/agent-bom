import { describe, expect, it } from "vitest";

import { emptyIssueSeverityMatrix, findingsHref } from "@/lib/finding-issue-type";

describe("finding-issue-type", () => {
  it("starts every issue type and the totals at zero", () => {
    const matrix = emptyIssueSeverityMatrix();
    expect(matrix.openTotal).toBe(0);
    expect(matrix.totals).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
    expect(Object.values(matrix.byType).every((count) => count === 0)).toBe(true);
  });

  it("builds findings deep links for severity and issue type", () => {
    expect(findingsHref({ severity: "critical", issue: "misconfiguration" })).toBe(
      "/findings?severity=critical&issue=misconfiguration",
    );
    expect(findingsHref({ kev: true })).toBe("/findings?kev=1");
    expect(findingsHref({ scope: "all", severity: "critical" })).toBe(
      "/findings?scope=all&severity=critical",
    );
  });
});
