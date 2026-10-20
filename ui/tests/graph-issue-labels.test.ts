import { describe, expect, it } from "vitest";

import { estateIssueLine, scopeContextLine, scopeIssueLine, scopeIssueShare } from "@/lib/graph-issue-labels";

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
