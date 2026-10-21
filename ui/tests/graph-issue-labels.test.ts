import { describe, expect, it } from "vitest";

import { estateIssueLine, scopeContextLine, scopeEstateComparison, scopeIssueLine, scopeIssueShare } from "@/lib/graph-issue-labels";

describe("estateIssueLine", () => {
  it("names issues and occurrences together so neither reads as the other", () => {
    expect(estateIssueLine({ issue_count: 1957, finding_occurrence_count: 2725 })).toBe("1,957 issues · 2,725 occurrences");
    expect(estateIssueLine({ issue_count: 1, finding_occurrence_count: 1 })).toBe("1 issue · 1 occurrence");
  });

  it("says nothing when the server sent no issue basis", () => {
    expect(estateIssueLine({})).toBeNull();
    expect(estateIssueLine(undefined)).toBeNull();
  });
});

describe("scopeIssueLine", () => {
  it("reads the same whether or not the estate total has loaded", () => {
    const item = { entity_type: "account", aggregate: { issue_count: 372, finding_occurrence_count: 372 } };
    expect(scopeIssueLine(item)).toBe("372 issues · 372 occurrences");
    expect(scopeIssueLine({ entity_type: "org", aggregate: {} })).toBeNull();
  });

  it("states the estate share separately, for a tooltip", () => {
    expect(scopeIssueShare({ entity_type: "account", aggregate: { issue_count: 372 } }, 1969)).toBe("372 of 1,969 estate issues are in this account");
    expect(scopeIssueShare({ entity_type: "org", aggregate: { issue_count: 10 } }, 10)).toBeUndefined();
    expect(scopeIssueShare({ entity_type: "org", aggregate: { issue_count: 10 } }, undefined)).toBeUndefined();
  });
});

describe("scopeContextLine", () => {
  it("drops context that only repeats the scope's own name", () => {
    expect(scopeContextLine({ label: "NORTHSTAR_02", context: { account: "NORTHSTAR_02" } })).toBeNull();
    expect(scopeContextLine({ label: "prod", context: { account: "PROD", region: "us-east-1" } })).toBe("region: us-east-1");
    expect(scopeContextLine({ label: "x", context: undefined })).toBeNull();
  });
});

describe("scopeEstateComparison", () => {
  const org = (critical: number, high: number, issues: number) => ({
    entity_type: "org", aggregate: { issue_count: issues, severity_counts: { critical, high } },
  });
  const estate = { issue_count: 1969, severity_counts: { critical: 332, high: 818 } };

  it("puts the scope's high beside the estate-wide high and names what lies outside", () => {
    expect(scopeEstateComparison(org(332, 813, 1947), estate)).toBe("813 high in this org · 818 estate-wide · 22 of 1,969 issues are outside this org");
  });

  it("names only the count outside when severity already agrees", () => {
    expect(scopeEstateComparison(org(332, 818, 1966), estate)).toBe("3 of 1,969 issues are outside this org (none critical or high)");
  });

  it("says nothing when the scope holds the whole estate or the estate total is unknown", () => {
    expect(scopeEstateComparison(org(332, 818, 1969), estate)).toBeNull();
    expect(scopeEstateComparison(org(332, 818, 1966), null)).toBeNull();
  });
});
