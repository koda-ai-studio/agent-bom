import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { FindingDrawer } from "@/components/finding-drawer";
import { severitySourceLabel, type UnifiedFinding } from "@/lib/api";
import { collectUnifiedFindings } from "@/lib/findings-adapter";
import type { EnrichedVuln } from "@/lib/findings-view";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => false }) }));

const base: EnrichedVuln = {
  id: "DSA-5514-1", severity: "high", packages: ["libc-bin"], agents: [],
  affected_servers: [], sources: [], exposed_credentials: [], reachable_tools: [],
  references: [], advisory_sources: [], remediation_items: [],
};

describe("severity from a linked CVE", () => {
  it("names the CVE and leaves other sources as they are", () => {
    expect(severitySourceLabel("upstream_cve:CVE-2023-4911")).toBe("Linked CVE CVE-2023-4911");
    expect(severitySourceLabel("cvss")).toBe("cvss");
    expect(severitySourceLabel(null)).toBeUndefined();
    expect(severitySourceLabel(undefined)).toBeUndefined();
  });

  it("shows the linked CVE and the note in the drawer", async () => {
    const note = "Based on 1 of 2 linked CVEs; CVE-2023-1 could not be looked up, so this may be understated.";
    render(
      <FindingDrawer
        vuln={{ ...base, severity_source: "upstream_cve:CVE-2023-4911", severity_note: note }}
        triage={undefined}
        triageBusy={false}
        onTriageDecision={vi.fn()}
        onClose={vi.fn()}
      />,
    );
    await userEvent.setup().click(screen.getByRole("tab", { name: "Evidence" }));
    expect(screen.getByText("Linked CVE CVE-2023-4911")).toBeVisible();
    expect(screen.getByText(note)).toBeVisible();
  });

  it("shows why an unrated finding has no severity", async () => {
    const note = "This advisory links no CVE, so it has no rating to inherit.";
    render(
      <FindingDrawer vuln={{ ...base, id: "DLA-3972-1", severity: "none", severity_note: note }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />,
    );
    await userEvent.setup().click(screen.getByRole("tab", { name: "Evidence" }));
    expect(screen.getByText(note)).toBeVisible();
  });

  it("carries the note from a finding's evidence", () => {
    const [row] = collectUnifiedFindings([
      {
        id: "f-1",
        finding_type: "CVE",
        severity: "high",
        title: "DSA-5514-1",
        asset: { name: "libc-bin", asset_type: "package" },
        evidence: { severity_note: "from evidence" },
      } as unknown as UnifiedFinding,
    ]);
    expect(row?.severity_note).toBe("from evidence");
  });
});
