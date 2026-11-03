import { afterEach, expect, it, vi } from "vitest";
import { scansApi } from "@/lib/api-scans";
import { _clearApiCacheForTests } from "@/lib/api";
afterEach(() => { vi.unstubAllGlobals(); _clearApiCacheForTests(); });
it("uses a compact display read and preserves the separate full export read", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ job_id: "x", status: "done" }), { headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fetch);
  await scansApi.getScanDashboard("x");
  expect(String(fetch.mock.calls[0]?.[0])).toMatch(/\/v1\/scan\/x\/dashboard$/);
  fetch.mockResolvedValue(new Response(JSON.stringify({ job_id: "x", status: "done" }), { headers: { "Content-Type": "application/json" } }));
  await scansApi.getScan("x");
  expect(String(fetch.mock.calls[1]?.[0])).toMatch(/\/v1\/scan\/x\?view=full$/);
});
