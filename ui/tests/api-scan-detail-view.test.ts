import { beforeEach, describe, expect, it, vi } from "vitest";

const get = vi.fn();
vi.mock("@/lib/api-transport", () => ({
  get: (...args: unknown[]) => get(...args),
  post: vi.fn(),
  del: vi.fn(),
  getBlob: vi.fn(),
  mutationIdempotencyKey: vi.fn(),
}));

import { scansApi } from "@/lib/api-scans";

describe("scan detail reads", () => {
  beforeEach(() => get.mockReset());

  it("opts into the full job because result views render the whole document", async () => {
    get.mockResolvedValue({ job_id: "job 1" });
    await scansApi.getScan("job 1");
    expect(get).toHaveBeenCalledWith("/v1/scan/job%201?view=full", {});
  });

  it("keeps lightweight polling on the status endpoint", async () => {
    get.mockResolvedValue({ job_id: "job-1" });
    await scansApi.getScanStatus("job-1");
    expect(get.mock.calls[0]![0]).toBe("/v1/scan/job-1/status");
  });
});
