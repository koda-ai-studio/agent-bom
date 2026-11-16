import { expect, test as base, type APIRequestContext } from "@playwright/test";

type SessionState = Awaited<ReturnType<APIRequestContext["storageState"]>> | undefined;

/** Share one in-memory login per worker without weakening the API's login rate limit. */
export const test = base.extend<{}, { demoSession: SessionState }>({
  demoSession: [async ({ playwright }, use, workerInfo) => {
    const api = process.env.AGENT_BOM_E2E_LIVE_API;
    if (!api) { await use(undefined); return; }
    const baseURL = workerInfo.project.use.baseURL;
    if (!baseURL) throw new Error("Live demo journeys require a configured UI baseURL");
    const request = await playwright.request.newContext({ baseURL });
    try {
      await expect.poll(async () => {
        const health = await request.get(`${api}/health`, { timeout: 5_000 }).catch(() => null);
        return health?.ok() ? (await health.json()).demo_seed : "unavailable";
      }, { message: "demo estate seed completes before journey assertions", timeout: 120_000, intervals: [1_000] }).toBe("complete");
      const key = process.env.AGENT_BOM_E2E_API_KEY;
      if (!key) { await use(undefined); return; }
      const response = await request.post("/v1/auth/session", { data: { api_key: key } });
      expect(response.ok(), "demo browser sign-in").toBe(true);
      await use(await request.storageState());
    } finally {
      await request.dispose();
    }
  }, { scope: "worker", timeout: 150_000 }],
  storageState: async ({ demoSession }, use) => { await use(demoSession); },
});
