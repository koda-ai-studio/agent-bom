import { describe, expect, it } from "vitest";

import { kevChipTitle } from "@/components/overview/issue-strip";
import { openIssueSeverity } from "@/lib/open-issue-counts";

const issues = {
  critical: 325,
  high: 814,
  medium: 10,
  low: 2,
  unrated: 1,
  total: 1152,
  approximate: false,
  basis: "issue_groups" as const,
};

describe("kevChipTitle", () => {
  it("states a lower bound while rows await backfill", () => {
    expect(kevChipTitle(5, 12, true)).toBe("At least 5 known-exploited issues (CISA KEV); older findings are still being indexed");
    expect(kevChipTitle(5, 12)).toBe("5 known-exploited issues (CISA KEV) · 12 findings");
  });
});

describe("openIssueSeverity", () => {
  it("prefers the issue-group counts the findings page shows over occurrence totals", () => {
    const result = openIssueSeverity({ critical: 428, high: 1265, medium: 20, low: 4, total: 1717, issues });
    expect(result).toMatchObject({ critical: 325, high: 814, medium: 10, low: 2, total: 1152 });
  });

  it("reads the exact occurrence counts when the issue block is a bounded walk", () => {
    const result = openIssueSeverity({
      critical: 30000,
      high: 150000,
      medium: 270000,
      low: 150000,
      total: 1000000,
      issues: { ...issues, critical: 4500, high: 13815, medium: 0, low: 0, total: 18315, approximate: true },
    });
    expect(result).toMatchObject({ critical: 30000, medium: 270000, total: 1000000 });
  });

  it("falls back to legacy occurrence counts when the server predates issue counts", () => {
    const result = openIssueSeverity({ critical: 3, high: 1, medium: 0, low: 0, total: 4 });
    expect(result).toEqual({ critical: 3, high: 1, medium: 0, low: 0, total: 4 });
  });

  it("returns null for missing input", () => {
    expect(openIssueSeverity(null)).toBeNull();
    expect(openIssueSeverity(undefined)).toBeNull();
  });
});
