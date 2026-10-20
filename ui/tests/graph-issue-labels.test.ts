import { describe, expect, it } from "vitest";

import { estateIssueLine, scopeIssueLine } from "@/lib/graph-issue-labels";

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
  it("states a scope's share of the estate's issues instead of an unlabelled smaller total", () => {
    expect(scopeIssueLine({ entity_type: "org", aggregate: { issue_count: 1933, finding_occurrence_count: 2700 } }, 1957)).toBe("1,933 of 1,957 issues in this org");
  });

  it("drops the share when the scope holds every issue or the estate total is unknown", () => {
    expect(scopeIssueLine({ entity_type: "account", aggregate: { issue_count: 88, finding_occurrence_count: 121 } }, undefined)).toBe("88 issues · 121 occurrences");
    expect(scopeIssueLine({ entity_type: "org", aggregate: { issue_count: 10, finding_occurrence_count: 10 } }, 10)).toBe("10 issues · 10 occurrences");
    expect(scopeIssueLine({ entity_type: "org", aggregate: {} }, 10)).toBeNull();
  });
});
