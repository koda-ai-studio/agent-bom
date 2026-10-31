import { expect, test } from "@playwright/test";
import { routeBaseline } from "./fixtures/route-catalog";

for (const theme of ["light", "dark"] as const) {
  test(`first session separates retained evidence from local preview in ${theme}`, async ({ page }, testInfo) => {
    await routeBaseline(page);
    await page.addInitScript((value) => {
      localStorage.setItem("agent-bom-theme", value);
      Object.defineProperty(navigator, "clipboard", { value: { writeText: async (text: string) => {
        document.documentElement.dataset.copiedCommand = text;
      } } });
    }, theme);
    await page.route("**/v1/auth/me", (route) => route.fulfill({ json: {
      authenticated: true, auth_method: "api_key", role: "admin", tenant_id: "first-session-fixture",
      permissions: ["read", "scan"], role_summary: { capabilities: ["scan.run"] },
    } }));
    await page.route("**/v1/jobs*", (route) => route.fulfill({ json: { jobs: [], total: 0 } }));
    await page.route("**/v1/overview", (route) => route.fulfill({ json: {
      schema_version: "overview.v1", tenant_id: "first-session-fixture",
      posture: { grade: null, score: null, summary: "No collection yet", breakdown: [] },
      headline: { scans: 0, critical: 0, high: 0, critical_high: 0, kev: 0, credential_exposed: 0, hub_findings: 0 },
      finding_counts: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0, total: 0, kev: 0 },
      domains: {}, coverage: [], top_risks: [],
    } }));
    const errors: string[] = [];
    const writes: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => {
      if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method())) writes.push(request.url());
    });
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.goto("/");
      const prompt = page.getByRole("region", { name: "Start with evidence" });
      await expect(prompt).toBeVisible();
      expect((await prompt.boundingBox())!.height).toBeLessThan(width === 390 ? 260 : 180);
      await expect(page.getByRole("heading", { name: "Send a local project" })).toHaveCount(0);
      await page.screenshot({ path: testInfo.outputPath(`overview-compact-${theme}-${width}.png`), fullPage: true });
      await prompt.getByRole("link", { name: "Get started" }).click();
      await expect(page).toHaveURL(/\/get-started\/?$/);
      await expect(page.getByRole("heading", { name: "Get started", exact: true })).toBeVisible();
      const guide = page.getByRole("region", { name: "Start with evidence" });
      await expect(guide).toBeVisible();
      await expect(guide.getByRole("link", { name: "Choose a scan target" })).toHaveAttribute("href", "/scan");
      await expect(guide.getByRole("link", { name: "Connect a source" })).toHaveAttribute("href", "/connections?tab=connect");
      await expect(guide.getByRole("list", { name: "Your first investigation" })).toBeVisible();
      await page.screenshot({ path: testInfo.outputPath(`first-session-${theme}-${width}.png`), fullPage: true });
      const disclosure = guide.locator("summary").filter({ hasText: "Show project command" });
      await disclosure.focus();
      await page.keyboard.press("Enter");
      await guide.getByRole("button", { name: "Copy project command" }).click();
      await expect(page.locator("html")).toHaveAttribute("data-copied-command", /--no-discover --context-graph.*AGENT_BOM_PUSH_URL:\?/);
      await expect(page.locator("html")).toHaveAttribute("data-copied-command", /^AGENT_BOM_PUSH_API_KEY=.*AGENT_BOM_PUSH_API_KEY:\?/);
      await expect(guide.getByText(/including any deployment prefix/)).toBeVisible();
      await guide.locator("summary").filter({ hasText: "Preview a saved or sample report" }).click();
      await expect(guide.getByText(/does not upload it to the control plane or populate its graph/)).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)).toBe(false);
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: testInfo.outputPath(`first-session-${theme}-${width}-expanded.png`), fullPage: true });
    }
    expect(writes).toEqual([]);
    expect(errors).toEqual([]);
  });
}
