import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { BriefEvidence } from "@/components/executive-brief/evidence";
const { apiMock } = vi.hoisted(() => ({ apiMock: { getComplianceVerificationKey: vi.fn(), downloadCompliancePack: vi.fn() } }));
vi.mock("@/lib/api", () => ({ api: apiMock }));
beforeEach(() => { vi.clearAllMocks(); URL.createObjectURL = vi.fn(() => "blob:pack"); URL.revokeObjectURL = vi.fn(); });
it("offers the public key for the server's Ed25519 contract without claiming verification", async () => {
  apiMock.getComplianceVerificationKey.mockResolvedValue({ algorithm: "Ed25519", signature_verifiable: true, public_key_pem: "public-key-placeholder", key_id: "key-one", verification_status: "verifiable_public_key" });
  render(<BriefEvidence sample={false} />);
  fireEvent.click(screen.getByRole("button", { name: "Check signing configuration" }));
  expect(await screen.findByRole("button", { name: "Download verification key" })).toBeVisible();
  expect(screen.getByText(/trusted channel/)).toBeVisible();
  expect(screen.getByText(/does not verify a bundle/)).toBeVisible();
});
it("downloads the pack through the authenticated transport", async () => {
  const blob = new Blob(['{"scope":"bounded"}']); apiMock.downloadCompliancePack.mockResolvedValue(blob);
  render(<BriefEvidence sample={false} />);
  fireEvent.click(screen.getByRole("button", { name: "Download signed pack" }));
  await waitFor(() => expect(URL.createObjectURL).toHaveBeenCalledWith(blob));
  expect(apiMock.downloadCompliancePack).toHaveBeenCalledOnce();
});
it("does not present sample signing as production evidence", () => {
  render(<BriefEvidence sample />);
  expect(screen.getByRole("button", { name: "Download signed pack" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Check signing configuration" })).toBeDisabled();
});
