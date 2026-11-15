import { describe, expect, it } from "vitest";

import type { JobListItem } from "@/lib/api";
import { jobEvidenceSummary } from "@/lib/job-evidence-summary";

const job = (summary: JobListItem["summary"]) => ({ summary }) as JobListItem;

describe("jobEvidenceSummary", () => {
  it("formats large counts with thousands separators", () => {
    const text = jobEvidenceSummary(job({ total_findings: 4722, critical_unified_findings: 1159, total_packages: 47220 } as JobListItem["summary"]));
    expect(text).toBe("4,722 findings · 1,159 critical · 47,220 packages");
  });

  it("formats legacy CVE totals the same way and keeps unavailable metrics named", () => {
    const text = jobEvidenceSummary(job({ total_vulnerabilities: 12056, critical_findings: 1200 } as JobListItem["summary"]));
    expect(text).toBe("12,056 CVEs · 1,200 critical · Unavailable packages");
    expect(jobEvidenceSummary(job(undefined))).toBe("Evidence metrics unavailable");
  });
});
