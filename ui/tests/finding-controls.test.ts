import { describe, expect, it } from "vitest";

import { complianceEvidenceHref, groupFindingControls } from "@/lib/finding-controls";

describe("groupFindingControls", () => {
  it("counts a control once even when the API also lists its legacy generic copy", () => {
    const groups = groupFindingControls(["cis:CIS-02.3", "generic:CIS-02.3", "iso_27001:A.5.19", "generic:A.5.19", "generic:LEGACY-1"]);
    // Same order as the compliance page sections; unmapped tags last.
    expect(groups.map((group) => group.label)).toEqual(["ISO 27001", "CIS Controls v8", "Other mappings"]);
    expect(groups.reduce((sum, group) => sum + group.controls.length, 0)).toBe(3);
  });

  it("links each control to its framework section and control on the compliance page", () => {
    const [cis] = groupFindingControls(["cis:CIS-02.3"]);
    expect(cis!.controls[0]).toEqual({ code: "CIS-02.3", href: "/compliance?framework=cis&control=CIS-02.3" });
  });

  it("normalises framework-prefixed control codes to the codes the compliance page lists", () => {
    const [fedramp] = groupFindingControls(["fedramp:FedRAMP-SI-2"]);
    expect(fedramp!.controls[0]).toEqual({ code: "SI-2", href: "/compliance?framework=fedramp&control=SI-2" });
  });

  it("merges structured controls with flat tags and leaves unmapped frameworks unlinked", () => {
    const groups = groupFindingControls(["generic:CUSTOM-1"], [{ framework: "soc2", control: "CC8.1" }]);
    expect(groups.find((group) => group.label === "SOC 2")!.controls[0]!.href).toBe("/compliance?framework=soc2&control=CC8.1");
    expect(groups.find((group) => group.label === "Other mappings")!.controls[0]!.href).toBeNull();
  });
});

describe("complianceEvidenceHref", () => {
  it("scopes the compliance page to the finding's package rather than opening it unfiltered", () => {
    expect(complianceEvidenceHref({ packages: ["langchain@0.0.150"], agents: [] })).toBe("/compliance?q=langchain");
    expect(complianceEvidenceHref({ packages: [], agents: ["langchain-service"] }, "scan-1")).toBe("/compliance?q=langchain-service&scan=scan-1");
    // The compliance search matches packages and agents, never advisory ids.
    expect(complianceEvidenceHref({ packages: ["asset"], agents: [] })).toBe("/compliance");
  });
});
