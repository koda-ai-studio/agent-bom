import { render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { ExposurePanel } from "@/components/advisories/exposure-panel";
import { getAffected, type AffectedAnswer } from "@/lib/incident-exposure";
vi.mock("@/lib/incident-exposure", async () => ({ ...await vi.importActual("@/lib/incident-exposure"), getAffected: vi.fn() }));
function answer(verdict: AffectedAnswer["verdict"]) {
  return { tenant_id: "fixture", query: { raw: "CVE-2026-1234", kind: "advisory" }, assets: [], assets_truncated: false, findings_truncated: false, findings_href: "/findings", inventory: { available: false, affected: 0, possibly_affected: 0, not_affected: 0, assets_examined: 0 }, verdict, verdict_basis: [], findings: { total: 0, open: 0, resolved: 0, fix_available: 0, no_fix: 0, suppressed: 0, severity: {}, kev: false, internet_exposed: 0, advisories: [], packages: [] }, exposure: { first_seen: null, last_seen: null, still_open: false, last_resolved_at: null }, reach: { by_kind: {}, items: {}, agents_on_findings: [], servers_on_findings: [], advisories_walked: [], basis: "unavailable", direction: "outbound", truncated: false, reasons: ["snapshot_changed"], complete: false, note: "Snapshot changed; retry." } } as AffectedAnswer;
}
it("does not turn missing matches into a clean security verdict", async () => {
  vi.mocked(getAffected).mockResolvedValue(answer("not_found"));
  render(<ExposurePanel query="CVE-2026-1234" />);
  expect(await screen.findByText("No match found")).toBeInTheDocument();
  expect(screen.queryByText("Not affected")).not.toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("not a complete assessment");
});
it("labels listed outbound reach and keeps failure evidence visible", async () => {
  vi.mocked(getAffected).mockResolvedValue(answer("affected"));
  render(<ExposurePanel query="CVE-2026-1234" />);
  expect(await screen.findByText("Outbound reach (listed)")).toBeInTheDocument();
  expect(screen.getByTestId("exposure-reach")).toHaveTextContent("incomplete or unavailable");
  expect(screen.getByText("Snapshot changed; retry.")).toBeInTheDocument();
});

it("does not describe historical or suppressed matches as all resolved", async () => {
  vi.mocked(getAffected).mockResolvedValue(answer("previously_affected"));
  render(<ExposurePanel query="CVE-2026-1234" />);
  expect(await screen.findByText("Previously affected")).toBeInTheDocument();
  expect(screen.queryByText(/all resolved/i)).not.toBeInTheDocument();
});
