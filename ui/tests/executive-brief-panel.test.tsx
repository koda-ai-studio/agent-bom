import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ExecutiveBriefPanel } from "@/components/executive-brief/panel";

const { apiMock, auth } = vi.hoisted(() => ({
  apiMock: { getExecutiveBrief: vi.fn(), downloadCompliancePack: vi.fn(), getComplianceVerificationKey: vi.fn() },
  auth: { session: { tenant_id: "tenant-a" } },
}));
vi.mock("@/lib/api", () => ({ api: apiMock }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => auth }));
const brief = {
  schema_version: "v1", document_type: "executive-brief", tenant_id: "tenant-a", generated_at: "2026-10-30T10:00:00Z", sample_data: true,
  posture: { summary: "Technical evidence needs review", grade: "C", no_data: false },
  issues: { total: 4, critical: 1, high: 2, kev: 1 },
  remediation_priorities: [{ vulnerability_id: "CVE-example", canonical_id: "finding/one", asset_id: "asset-a", package: "example", owner: "team-a", sla_due_at: null, sla_due_at_source: "unknown", severity: "high" }],
  exposure_status: "unavailable", exposure_paths: null,
  compliance: { overall_status: "warning", evaluated_controls: 3, total_controls: 20, frameworks: {}, latest_scan: "control-scan" },
  scan_history: { data_points: [{ scan_id: "history-scan", timestamp: "2026-10-29T10:00:00Z", comparison: { status: "not_comparable", reason: "different_scope" } }] },
  scope: { consistency: "independent_source_reads", exposure_scan_id: "graph-scan", requested_priority_limit: 5 },
  links: { evidence_pack: "/v1/compliance/report/pack", verification_key: "/v1/compliance/verification-key", findings: "/v1/findings", exposure_paths: "/v1/graph/attack-paths" },
  evidence_boundary: "This unsigned brief summarizes technical evidence, not compliance attestation or confirmed exploitation.",
};
beforeEach(() => {
  Object.values(apiMock).forEach(fn => fn.mockReset());
  auth.session = { tenant_id: "tenant-a" };
  apiMock.getExecutiveBrief.mockResolvedValue(structuredClone(brief));
  URL.createObjectURL = vi.fn(() => "blob:brief"); URL.revokeObjectURL = vi.fn();
});
it("previews canonical counts, sample and unavailable evidence with scoped drilldowns", async () => {
  render(<ExecutiveBriefPanel />);
  expect(await screen.findByText("Technical evidence needs review")).toBeVisible();
  expect(screen.getByText("Sample data")).toBeVisible();
  expect(screen.getByText(/Path evidence unavailable/)).toBeVisible();
  expect(screen.getByText(/different_scope/)).toBeVisible();
  expect(screen.getByRole("link", { name: /CVE-example/ })).toHaveAttribute("href", "/findings?finding=finding%2Fone");
  expect(screen.getByRole("button", { name: "Download Markdown" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Download JSON" })).toBeEnabled();
});
it("never offers stale content after refresh fails", async () => {
  render(<ExecutiveBriefPanel />); await screen.findByText("Technical evidence needs review");
  apiMock.getExecutiveBrief.mockRejectedValue(new Error("private-backend-string"));
  fireEvent.click(screen.getByRole("button", { name: "Refresh brief" }));
  expect(await screen.findByText(/Brief unavailable/)).toBeVisible();
  expect(screen.queryByText("Technical evidence needs review")).toBeNull();
  expect(screen.queryByRole("button", { name: "Download JSON" })).toBeNull();
  expect(screen.queryByText("private-backend-string")).toBeNull();
});
it("ignores an older tenant response after a session change", async () => {
  let finish: (value: unknown) => void = () => {};
  apiMock.getExecutiveBrief.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
  const view = render(<ExecutiveBriefPanel />);
  auth.session = { tenant_id: "tenant-b" };
  apiMock.getExecutiveBrief.mockResolvedValue({ ...brief, tenant_id: "tenant-b", posture: { summary: "Tenant B evidence" } });
  view.rerender(<ExecutiveBriefPanel />);
  await screen.findByText("Tenant B evidence");
  finish(brief);
  await waitFor(() => expect(screen.queryByText("Technical evidence needs review")).toBeNull());
});
it("keeps signed pack verification separate and exposes unverifiable signing honestly", async () => {
  apiMock.getExecutiveBrief.mockResolvedValue({ ...brief, sample_data: false });
  apiMock.getComplianceVerificationKey.mockResolvedValue({ algorithm: "hmac-sha256", signature_verifiable: false, verification_status: "unverifiable_ephemeral_key", public_key_pem: null });
  render(<ExecutiveBriefPanel />); await screen.findByText("Technical evidence needs review");
  fireEvent.click(screen.getByRole("button", { name: "Check signing configuration" }));
  expect(await screen.findByText(/unverifiable_ephemeral_key/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Download verification key" })).toBeNull();
  expect(screen.getByText(/does not verify a bundle/)).toBeVisible();
});
it("downloads the same scoped preview without fetching a different summary", async () => {
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  const created = vi.spyOn(document, "createElement");
  render(<ExecutiveBriefPanel />); await screen.findByText("Technical evidence needs review");
  fireEvent.click(screen.getByRole("button", { name: "Download JSON" }));
  expect(apiMock.getExecutiveBrief).toHaveBeenCalledOnce();
  expect(URL.createObjectURL).toHaveBeenCalledOnce();
  const anchor = created.mock.results.map(result => result.value).find(value => value instanceof HTMLAnchorElement && value.download === "executive-brief.json");
  expect(anchor).toBeDefined();
  click.mockRestore(); created.mockRestore();
});
