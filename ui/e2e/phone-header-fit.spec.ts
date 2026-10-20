import { expect, test } from "@playwright/test";

const labels = [
  ["demo", "/?capture=1", /^Demo data/],
  ["reference lab", "/?capture=1&scan=reference-evidence-correlation-v1", /^Reference lab/],
] as const;

for (const [name, url, text] of labels) {
  test(`phone header keeps the brand and every control on screen with the ${name} label`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.route("**/v1/**", (route) => route.fulfill({ json: {} }));
    await page.route("**/health", (route) => route.fulfill({ json: { status: "ok", version: "1.0.0" } }));
    await page.goto(url);
    const label = page.locator("#demo-estate-watermark");
    await expect(label).toBeVisible();
    await expect(label.locator("span:visible")).toHaveText(text);
    const controls = [
      page.getByRole("link", { name: "agent-bom", exact: true }),
      label,
      page.getByRole("button", { name: "Search pages", exact: true }),
      page.getByRole("button", { name: /Switch to .* theme/ }),
      page.locator("header summary[aria-label^='Account menu:']"),
      page.getByRole("button", { name: "Open navigation menu" }),
      page.locator("header summary[aria-label^='Control plane']"),
    ];
    for (const control of controls) {
      const bounds = await control.boundingBox();
      expect(bounds).not.toBeNull();
      expect(bounds!.x).toBeGreaterThanOrEqual(0);
      expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
    }
    // Phones show the status dot; the full label stays in the summary's accessible name and its popover.
    await expect(page.locator("header summary[aria-label^='Control plane'] span:not([class*='rounded-full'])")).toBeHidden();
    const mark = await page.getByRole("link", { name: "agent-bom", exact: true }).boundingBox();
    expect(mark!.width).toBeGreaterThanOrEqual(36);
    await page.getByRole("banner").screenshot({ path: test.info().outputPath(`header-${name.replace(" ", "-")}-390.png`) });
  });
}
