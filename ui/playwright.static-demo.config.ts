import { defineConfig, devices } from "@playwright/test";

/**
 * Browser checks against the built read-only demo (`out/` from
 * `NEXT_EXPORT=1 NEXT_PUBLIC_STATIC_DEMO=1 NEXT_PUBLIC_BASE_PATH=/agent-bom/demo npm run build`
 * followed by `node scripts/generate-static-demo-data.mjs`). Each spec serves
 * `out/` itself; nothing here needs a dev server or an API.
 *
 *   npx playwright test --config playwright.static-demo.config.ts
 */
export default defineConfig({
  testDir: "./e2e-static-demo",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: { trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
