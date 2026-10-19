import { createHash } from "node:crypto";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LineageDetailPanel } from "@/components/lineage-detail";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { NODE_LABELS } from "@/lib/entity-labels";

const rich: Partial<LineageNodeData> = {
  description: "Recorded evidence", version: "1.2.3", ecosystem: "npm",
  agentType: "claude-code", agentStatus: "installed-not-configured", agentCount: 2,
  serverCount: 3, packageCount: 4, vulnCount: 2, vulnCountPartial: true,
  toolCount: 2, credentialCount: 1, command: "example --stdio", sharedBy: 2,
  sharedAgents: ["agent-a", "agent-b"], versionSource: "lockfile", versionConfidence: "exact",
  severity: "high", cvssScore: 8.1, epssScore: 0.1, isKev: true, fixedVersion: "1.2.4",
  owaspTags: ["LLM01"], atlasTags: ["AML.T0001"], serverName: "Example server",
  status: "active", riskScore: 80, firstSeen: "2026-01-01", lastSeen: "2026-01-02",
  evidenceTier: "replay_only", evidenceCaptureReplay: true, evidenceNotAfter: "2026-01-05",
  runtimeEvidenceTier: "runtime_observed", dataSources: ["scan/a"], complianceTags: ["CIS/1"],
  neighborCount: 2, sourceCount: 1, incomingEdgeCount: 1, outgoingEdgeCount: 2,
  impactCount: 2, maxImpactDepth: 1, impactByType: { agent: 2 }, relationshipCountsPartial: true,
  impactCompleteness: { status: "truncated", complete: false, truncated: true, sampled: false, returned: 2, reason: "depth_limit" },
  attributes: { node_id: "example:node", verified: true, extra_flag: false, custom: ["a", "b"] },
};

const digest = (html: string) => createHash("sha256").update(html).digest("hex");
beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-01-03T00:00:00Z"));
  vi.spyOn(Date.prototype, "toLocaleString").mockImplementation(function (this: Date) { return this.toISOString(); });
  localStorage.clear();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("lineage inspector rendering before extraction", () => {
  it.each(Object.keys(NODE_LABELS) as LineageNodeData["nodeType"][])("preserves the %s overview DOM", nodeType => {
    const { container } = render(<LineageDetailPanel data={{ ...rich, label: "CVE-2025-12345", nodeType }}
      variant="inline" onClose={() => {}} onShowBlastRadius={() => {}}
      headerSlot={<p>Header evidence</p>} footerSlot={<button>Next action</button>} />);
    expect(digest(container.innerHTML)).toMatchSnapshot();
  });

  it.each(["inline", "overlay", "docked"] as const)("preserves all tabs in %s mode", variant => {
    const { container } = render(<LineageDetailPanel data={{ ...rich, label: "Package", nodeType: "package" }}
      variant={variant} onClose={() => {}} relationshipSlot={<p>Recorded links</p>} />);
    for (const label of ["Overview", "Relationships", "Impact", "Attributes"]) {
      fireEvent.click(screen.getByRole("tab", { name: label }));
      expect(digest(container.innerHTML)).toMatchSnapshot(label);
    }
  });

  it("preserves collapse, callback, and missing-tab fallback", () => {
    const close = vi.fn(), blast = vi.fn();
    const { rerender } = render(<LineageDetailPanel data={{ ...rich, label: "Package", nodeType: "package" }}
      variant="docked" onClose={close} onShowBlastRadius={blast} />);
    fireEvent.click(screen.getByRole("button", { name: "Show blast radius" }));
    expect(blast).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole("button", { name: "Collapse details" }));
    expect(screen.getByTestId("graph-entity-drawer-collapsed")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Show node details" }));
    fireEvent.click(screen.getByRole("tab", { name: "Impact" }));
    rerender(<LineageDetailPanel data={{ label: "Other", nodeType: "package" }} variant="docked" onClose={close} />);
    expect(screen.getByTestId("graph-drawer-panel-overview")).toHaveTextContent("Finding count unavailable");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(close).toHaveBeenCalledOnce();
  });
});
