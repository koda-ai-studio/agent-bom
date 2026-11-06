import { expect, test } from "@playwright/test";

// No mocks: the page talks to a running API that did a real scan. Skipped unless pointed at one.
const backend = process.env.AI_REAL_BACKEND_URL;
const apiKey = process.env.AI_REAL_BACKEND_KEY ?? "";
const expected = process.env.AI_REAL_EXPECT ?? "on";
const label = process.env.AI_REAL_LABEL ?? "real";

test.skip(!backend, "AI_REAL_BACKEND_URL is not set");
test.use({ baseURL: backend, extraHTTPHeaders: { "X-API-Key": apiKey } });

const STATUS: Record<string, RegExp> = {
  on: /AI advice is on/,
  off: /^AI advice is off: the operator has not set AGENT_BOM_AI_CONTROL_PLANE_ENABLED\.$/,
  failed: /last AI run failed.*Scanner findings are unaffected/,
};

for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    test(`${label} findings and drawer ${theme} ${width}`, async ({ page }, testInfo) => {
      test.setTimeout(120_000);
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
      await page.goto("/findings");
      await expect(page.getByRole("status").filter({ hasText: /AI advice|AI run/ })).toHaveText(STATUS[expected]!, { timeout: 30_000 });
      await expect(page.getByRole("button", { name: "Investigate" }).first()).toBeVisible({ timeout: 60_000 });
      await page.screenshot({ path: testInfo.outputPath(`${label}-findings-${theme}-${width}.png`), fullPage: width > 500 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      const badges = page.getByLabel(/^AI advice: /);
      if (expected !== "on") return;
      await expect(badges.first()).toBeVisible({ timeout: 30_000 });
      const row = page.getByRole("button", { name: /^Open details for / }).filter({ has: badges.first() }).first();
      if (await row.count()) await row.click();
      else await page.locator("tr", { has: badges.first() }).getByRole("button", { name: "Investigate" }).first().click();
      const section = page.getByRole("region", { name: "AI advice" });
      await expect(section).toContainText("confidence");
      await expect(section).toContainText("ollama/qwen2.5:3b");
      await expect(section).toContainText("does not change scanner severity");
      await page.waitForTimeout(800);
      await page.screenshot({ path: testInfo.outputPath(`${label}-drawer-${theme}-${width}.png`), animations: "disabled" });
    });
  }

  test(`${label} explain panel ${theme}`, async ({ page }, testInfo) => {
    test.setTimeout(240_000);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
    await page.goto("/security-graph?lens=attack-path");
    const button = page.getByRole("button", { name: "Explain this path" });
    await expect(button).toBeVisible({ timeout: 60_000 });
    await button.click();
    if (expected === "on") {
      const panel = page.getByRole("region", { name: "Path explanation, AI advice" });
      await expect(panel).toContainText("What the graph does not show", { timeout: 180_000 });
      await panel.scrollIntoViewIfNeeded();
      await expect(panel.locator("a")).toHaveCount(0);
    } else {
      await expect(page.getByRole("alert").filter({ hasText: /AI advice is off|not reachable|withheld|unavailable|Ollama|ollama/ })).toBeVisible({ timeout: 60_000 });
    }
    await page.screenshot({ path: testInfo.outputPath(`${label}-explain-${theme}.png`) });
  });
}
