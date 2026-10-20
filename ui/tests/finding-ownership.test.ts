import { describe, expect, it } from "vitest";

import { ownershipSummary, pathLeadFinding } from "@/lib/finding-ownership";

const now = Date.parse("2026-10-19T00:00:00Z");

describe("ownership summary", () => {
  it("names an assigned owner and a policy SLA with days remaining", () => {
    const summary = ownershipSummary({ owner: "platform-team", sla_due_at: "2026-10-26T00:00:00Z", sla_due_at_source: "severity-kev/v1" }, now);
    expect(summary.owner).toBe("platform-team");
    expect(summary.ownerLabel).toBe("platform-team");
    expect(summary.slaLabel).toBe("Due in 7 days");
    expect(summary.slaState).toBe("due");
    expect(summary.basis).toBe("Severity and KEV policy");
  });

  it("says unassigned plainly and flags an overdue SLA", () => {
    const summary = ownershipSummary({ owner: null, sla_due_at: "2026-10-16T00:00:00Z", sla_due_at_source: "explicit" }, now);
    expect(summary.owner).toBeNull();
    expect(summary.ownerLabel).toBe("Unassigned");
    expect(summary.slaLabel).toBe("Overdue by 3 days");
    expect(summary.slaState).toBe("overdue");
    expect(summary.basis).toBe("Explicit due date");
  });

  it("never invents an SLA", () => {
    const summary = ownershipSummary({}, now);
    expect(summary.slaLabel).toBe("No SLA recorded");
    expect(summary.slaState).toBe("none");
    expect(summary.dueDate).toBeNull();
  });
});

describe("path lead finding", () => {
  const rows = [
    { finding_id: "image", node_id: "pkg:pypi:langchain@0.0.150:image:abc", package: "langchain@0.0.150" },
    { finding_id: "agent", node_id: "pkg:pypi:langchain@0.0.150", package: "langchain@0.0.150" },
  ];

  it("picks the occurrence whose node is on the path", () => {
    expect(pathLeadFinding(rows, ["agent:svc", "pkg:pypi:langchain@0.0.150", "vuln:CVE-1"], "langchain@0.0.150")?.finding_id).toBe("agent");
  });

  it("falls back to the package label, else nothing", () => {
    expect(pathLeadFinding([rows[0]!], ["pkg:other"], "langchain@0.0.150")?.finding_id).toBe("image");
    expect(pathLeadFinding(rows, ["pkg:other"], "other@1")).toBeNull();
  });
});
