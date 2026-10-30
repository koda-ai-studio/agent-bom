import { expect, it, vi } from "vitest";
const { get, getBlob } = vi.hoisted(() => ({ get: vi.fn(), getBlob: vi.fn() }));
vi.mock("@/lib/api-transport", () => ({ get, getBlob, put: vi.fn(), DEMO_STORY_TIMEOUT_MS: 30000 }));
import { postureApi } from "@/lib/api-posture";
it("routes brief and evidence reads through the established authenticated transport", async () => {
  await postureApi.getExecutiveBrief(); await postureApi.getComplianceVerificationKey(); await postureApi.downloadCompliancePack();
  expect(get).toHaveBeenCalledWith("/v1/brief", { force: true, signal: undefined });
  expect(get).toHaveBeenCalledWith("/v1/compliance/verification-key", { force: true });
  expect(getBlob).toHaveBeenCalledWith("/v1/compliance/report/pack");
});
