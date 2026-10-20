import { expect, test, type Page } from "@playwright/test";

/**
 * GRC evidence journey and readability floors against a running demo-estate API.
 *
 * Opt-in like count-consistency-live: start `agent-bom api` with the demo estate,
 * point the UI at it and run with AGENT_BOM_E2E_LIVE_API=http://127.0.0.1:<port>.
 * When the API requires a key, AGENT_BOM_E2E_API_KEY signs the browser in.
 */
const LIVE_API = process.env.AGENT_BOM_E2E_LIVE_API ?? "";
const API_KEY = process.env.AGENT_BOM_E2E_API_KEY ?? "";

test.skip(!LIVE_API, "Set AGENT_BOM_E2E_LIVE_API to a demo-estate API the UI dev server reads");
test.describe.configure({ timeout: 180_000 });

async function signIn(page: Page) {
  if (!API_KEY) return;
  const response = await page.request.post("/v1/auth/session", { data: { api_key: API_KEY } });
  expect(response.ok()).toBe(true);
}

async function open(page: Page, path: string) {
  await page.goto(path, { timeout: 120_000 });
  await page.waitForLoadState("networkidle", { timeout: 60_000 }).catch(() => undefined);
}

/** Visible text nodes rendered below 12px, outside the zoomable canvas. */
async function smallChromeText(page: Page) {
  return page.evaluate(() => {
    const small: string[] = [];
    for (const element of document.querySelectorAll("body *")) {
      if (element.closest(".react-flow, canvas, svg")) continue;
      const ownText = [...element.childNodes].some((node) => node.nodeType === Node.TEXT_NODE && node.textContent?.trim());
      if (!ownText) continue;
      const box = element.getBoundingClientRect();
      if (!box.width || !box.height) continue;
      const size = parseFloat(getComputedStyle(element).fontSize);
      if (size < 12) small.push(`${size}px ${element.textContent?.trim().slice(0, 40)}`);
    }
    return small;
  });
}

test("a GRC reader reaches a mapped asset in the graph within three clicks of a framework", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await open(page, "/compliance");
  await page.getByTestId("compliance-frameworks-table").getByText("AI RMF", { exact: true }).click();
  await page.getByText("GOVERN-6.1", { exact: true }).first().click();
  const drawer = page.getByRole("dialog", { name: /Control details for GOVERN-6\.1/ });
  await expect(drawer.getByRole("tab", { name: "Evidence" })).toHaveAttribute("aria-selected", "true");
  const summary = drawer.getByTestId("control-evidence-summary");
  await expect(summary).toContainText(/\d[\d,]* findings carry/);
  await expect(summary).toContainText(/\d[\d,]* attack paths? support this control/);
  await expect(summary).toContainText("Counted by control-tag evidence");
  const findings = drawer.getByRole("list", { name: "Findings mapped to GOVERN-6.1" });
  await expect(findings.getByRole("listitem").first()).toBeVisible();
  await drawer.getByRole("button", { name: /^Attack paths/ }).click();
  await expect(drawer.getByTestId("path-support-reason").first()).toContainText(/Ends on .+GOVERN-6\.1/);
  await drawer.getByRole("button", { name: /^Findings & assets/ }).click();
  const graphLink = findings.getByRole("link", { name: /^Open .+ in the graph$/ }).first();
  await graphLink.click();
  await expect(page).toHaveURL(/\/security-graph\?.*lens=attack-path.*finding=/);
  await expect(page.getByRole("main")).toBeVisible();
});

test("the Cloud filter replaces an AI framework pane", async ({ page }) => {
  await signIn(page);
  await open(page, "/compliance");
  await page.getByTestId("compliance-frameworks-table").getByText("AI RMF", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "NIST AI RMF 1.0" })).toBeVisible();
  await page.getByRole("button", { name: "cloud", exact: true }).click();
  await expect(page.getByRole("heading", { name: "NIST AI RMF 1.0" })).toHaveCount(0);
});

test("security-graph chrome text is at least 12px", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await open(page, "/security-graph");
  await expect(page.locator(".react-flow").first()).toBeVisible({ timeout: 60_000 });
  expect(await smallChromeText(page)).toEqual([]);
});

for (const path of ["/findings", "/graph"]) {
  test(`${path} fits a 390px phone at 200% text`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await signIn(page);
    await open(page, path);
    await expect(page.getByRole("main")).toBeVisible();
    await page.waitForTimeout(3_000);
    await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
    await page.waitForTimeout(1_500);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    const chip = page.locator("#demo-estate-watermark");
    if (await chip.count()) {
      expect(await chip.evaluate((element) => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
      const chipBox = await chip.boundingBox();
      const search = await page.getByRole("button", { name: "Search pages", exact: true }).boundingBox();
      expect(chipBox!.x + chipBox!.width).toBeLessThanOrEqual(search!.x);
      const text = (await chip.locator("span:visible").allTextContents()).join("");
      expect(text === "" ? await chip.locator("svg").isVisible() : /^Demo/.test(text)).toBe(true);
    }
  });
}

test("/graph header controls never overlap the title at 200% text on a phone", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page);
  await open(page, "/graph");
  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  await page.waitForTimeout(500);
  const title = await page.getByRole("heading", { level: 1 }).first().boundingBox();
  const control = await page.getByText("Snapshot & view", { exact: true }).first().boundingBox();
  expect(title).not.toBeNull();
  if (control && title) {
    const overlaps = control.x < title.x + title.width && control.x + control.width > title.x
      && control.y < title.y + title.height && control.y + control.height > title.y;
    expect(overlaps).toBe(false);
  }
});
