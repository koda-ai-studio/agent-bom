import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ScanInvestigationEntry } from "@/components/scan-investigation-entry";
const mocks = vi.hoisted(() => ({ replace: vi.fn(), getScanStatus: vi.fn(), session: {tenant_id: "tenant-a", subject: "reader", auth_method: "session"} as {tenant_id: string; subject: string; auth_method: string} | null }));
const router = { replace: mocks.replace };
vi.mock("next/navigation", () => ({ useRouter: () => router }));
vi.mock("@/lib/api", () => ({ api: {getScanStatus: mocks.getScanStatus} }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({session: mocks.session}) }));
beforeEach(() => { vi.clearAllMocks(); mocks.session = {tenant_id: "tenant-a", subject: "reader", auth_method: "session"}; });
for (const path of [false, true]) it(`resolves the exact persisted snapshot for old ${path ? "path" : "mesh"} URLs`, async () => {
  mocks.getScanStatus.mockResolvedValue({graph_scan_id: "snapshot/+&?"});
  render(<ScanInvestigationEntry id="job" path={path} />);
  await waitFor(() => expect(mocks.replace).toHaveBeenCalledTimes(1));
  const url = new URL(mocks.replace.mock.calls[0]![0], "http://local");
  expect(url.pathname).toBe("/security-graph");
  expect(url.searchParams.get("scan")).toBe("snapshot/+&?");
  expect(url.searchParams.get("lens")).toBe(path ? "attack-path" : "estate");
});
it("does not substitute the job ID when a snapshot was never recorded", async () => {
  mocks.getScanStatus.mockResolvedValue({graph_scan_id: null});
  render(<ScanInvestigationEntry id="job" />);
  expect(await screen.findByRole("alert")).toHaveTextContent("no recorded graph snapshot");
  expect(mocks.replace).not.toHaveBeenCalled();
  expect(screen.getByRole("link", {name: "Open scan report"})).toHaveAttribute("href", "/scan?id=job");
});
it("never displays raw lookup errors", async () => {
  mocks.getScanStatus.mockRejectedValue(new Error("private-secret-path"));
  render(<ScanInvestigationEntry id="job" />);
  expect(await screen.findByRole("alert")).not.toHaveTextContent("private-secret-path");
});
it("revokes pending navigation at logout", async () => {
  let finish!: (value: unknown) => void;
  mocks.getScanStatus.mockImplementation(() => new Promise(resolve => {finish = resolve;}));
  const view = render(<ScanInvestigationEntry id="job" />);
  mocks.session = null; view.rerender(<ScanInvestigationEntry id="job" />);
  expect(mocks.getScanStatus.mock.calls[0]![1].aborted).toBe(true);
  await act(async () => finish({graph_scan_id: "old-tenant"}));
  expect(mocks.replace).not.toHaveBeenCalled();
});
