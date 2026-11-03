import { describe, expect, it } from "vitest";

import { complianceHeadline, type ComplianceFrameworkSummary } from "@/lib/compliance-frameworks";

const row = (pass: number, warn: number, fail: number, kind: "scored" | "applicability" = "scored") =>
  ({ id: `f-${pass}-${warn}-${fail}-${kind}`, kind, pass, warn, fail, total: pass + warn + fail + 2 }) as unknown as ComplianceFrameworkSummary;

describe("complianceHeadline", () => {
  it("never shows a pass rate when no scored control was evaluated, whatever the API score says", () => {
    const headline = complianceHeadline([row(0, 0, 0), row(0, 0, 0, "applicability")], { overall_status: "warning", total_controls: 12 });
    expect(headline).toEqual({ evaluated: 0, total: 12, rate: null, status: "no_data" });
  });

  it("derives the rate from the same rows the passing, attention and failing tiles sum", () => {
    const headline = complianceHeadline([row(3, 0, 1), row(2, 1, 0)], { overall_status: "fail", total_controls: 20 });
    expect(headline.evaluated).toBe(7);
    expect(headline.rate).toBe(Math.round((5 / 7) * 100));
    expect(headline.status).toBe("fail");
  });

  it("ignores applicability catalogs, which are never scored", () => {
    expect(complianceHeadline([row(5, 0, 0, "applicability")], { overall_status: "pass", total_controls: 5 }).rate).toBeNull();
  });
});
