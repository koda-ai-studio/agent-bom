import { expect, test, type Page } from "@playwright/test";
import path from "node:path";

import { startStaticDemoServer } from "../scripts/static-demo-server.mjs";

const BASE_PATH = "/agent-bom/demo";
const OUT_DIR = path.resolve(process.cwd(), process.env.STATIC_DEMO_OUT ?? "out");

let server: { origin: string; close: () => Promise<unknown> };
test.beforeAll(async () => { server = await startStaticDemoServer(OUT_DIR, BASE_PATH); });
test.afterAll(async () => { await server.close(); });

const url = (route: string) => `${server.origin}${BASE_PATH}${route}`;
const viewportTransform = (page: Page) => page.locator(".react-flow__viewport").first().evaluate((el) => el.getAttribute("style") ?? "");
/** Nodes (labels included) outside the canvas or under its zoom controls. */
const nodesOutsideCanvas = (page: Page) => page.locator(".react-flow").first().evaluate((flow) => {
  const box = flow.getBoundingClientRect();
  const controls = flow.querySelector(".react-flow__controls")?.getBoundingClientRect();
  const overlaps = (rect: DOMRect, other: DOMRect) => rect.left < other.right && rect.right > other.left && rect.top < other.bottom && rect.bottom > other.top;
  return [...flow.querySelectorAll(".react-flow__node")].filter((node) => {
    const rect = node.getBoundingClientRect();
    return rect.top < box.top || rect.bottom > box.bottom || rect.left < box.left || rect.right > box.right || (controls ? overlaps(rect, controls) : false);
  }).map((node) => node.textContent?.slice(0, 24));
});

async function openInvestigation(page: Page, route = "/security-graph") {
  await page.goto(url(route), { waitUntil: "networkidle" });
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  await page.waitForTimeout(600);
}

test("a plain wheel over the path canvas scrolls the page; Ctrl + wheel zooms the graph", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openInvestigation(page);
  const canvas = page.locator(".react-flow").first();
  const box = (await canvas.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  const before = await viewportTransform(page);
  await page.mouse.wheel(0, 240);
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  expect(await viewportTransform(page)).toBe(before);
  await expect(page.getByTestId("wheel-zoom-hint")).toContainText("scroll to zoom");

  await page.keyboard.down("Control");
  await page.mouse.wheel(0, -240);
  await page.keyboard.up("Control");
  await page.waitForTimeout(300);
  expect(await viewportTransform(page)).not.toBe(before);
});

test("the selected path fits the canvas even when a stale viewport was saved for it", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openInvestigation(page);
  expect(await nodesOutsideCanvas(page)).toEqual([]);
  const rewritten = await page.evaluate(() => {
    let count = 0;
    for (const key of Object.keys(localStorage)) {
      if (!key.startsWith("agent-bom:graph-presentation:v1:") || key.includes(":owner:")) continue;
      const saved = JSON.parse(localStorage.getItem(key) ?? "{}");
      if (!saved.viewport) continue;
      saved.viewport = { x: 40, y: 620, zoom: 0.7 };
      localStorage.setItem(key, JSON.stringify(saved));
      count += 1;
    }
    return count;
  });
  expect(rewritten).toBeGreaterThan(0);
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  await page.waitForTimeout(800);
  expect(await nodesOutsideCanvas(page)).toEqual([]);
});

test("Impact, Owner and Verify steps show sample evidence for the headline path", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openInvestigation(page, "/security-graph?step=impact");
  const impact = page.getByRole("region", { name: "Path impact" });
  await expect(impact).toContainText(/\d+ assets? exposed to this finding/);
  await expect(impact.getByRole("alert")).toHaveCount(0);

  await openInvestigation(page, "/security-graph?step=owner");
  const owner = page.getByRole("region", { name: "Path owner" });
  await expect(owner).toContainText("data-platform");
  await expect(owner).toContainText("Remediation SLA");
  await expect(owner.getByRole("alert")).toHaveCount(0);

  await page.goto(url("/remediation?view=verification"), { waitUntil: "networkidle" });
  await expect(page.getByText("Awaiting re-verification")).toBeVisible();
  await expect(page.getByText("no sample data in the read-only demo")).toHaveCount(0);
});

test("findings lanes carry counts and the audit log records outcomes", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(url("/findings"), { waitUntil: "networkidle" });
  const vulnerabilities = page.getByRole("tab", { name: /^Vulnerabilities/ });
  await expect(vulnerabilities).toBeVisible();
  await expect(vulnerabilities).not.toContainText("—");
  await expect(vulnerabilities).toContainText(/\d+/);

  await page.goto(url("/audit"), { waitUntil: "networkidle" });
  await expect(page.locator("#main-content")).toContainText(/completed|denied|issued/);
  await expect(page.locator("#main-content")).not.toContainText("Not recorded");
});

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`sample onboarding and source browsing ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.goto(url("/demo-estate"), { waitUntil: "networkidle" });
    await expect(page.getByRole("heading", { name: "Explore the sample estate" })).toBeVisible();
    await page.getByRole("link", { name: "Inspect sample sources" }).click();
    await expect(page.getByRole("table")).toBeVisible();
    await expect(page.getByRole("button", { name: "Register a source" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Add cloud account" })).toHaveCount(0);
    await expect(page.getByTestId("connections-scheduler-disabled-banner")).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`sample-sources-${theme}-${width}.png`), fullPage: true });
  });
}

test("unrecorded severity and scan filters resolve from the bundled findings", async ({ page }) => {
  await page.goto(url("/findings?lane=all&scan=scan-proof-ai-platform&severity=high"), { waitUntil: "networkidle" });
  await expect(page.getByText("Findings need the agent-bom API")).toHaveCount(0);
  await expect(page.getByText("Total unavailable", { exact: false })).toHaveCount(0);
  await expect(page.getByRole("tab", { name: /^Vulnerabilities/ })).toContainText(/\d+/);
  await expect(page.getByRole("tab", { name: /^Cloud config/ })).toContainText("0");
});

test("relationship labels can be hidden without losing the path", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openInvestigation(page);
  const labels = page.getByRole("combobox", { name: "Relationship labels" });
  await expect(labels).toBeVisible();
  const edges = await page.locator(".react-flow__edge").count();
  await labels.selectOption("show");
  await expect(page.locator(".graph-relationship-label").first()).toBeVisible();
  await labels.selectOption("hide");
  await expect(page.locator(".graph-relationship-label")).toHaveCount(0);
  await expect(page.locator(".react-flow__edge")).toHaveCount(edges);
});

for (const theme of ["dark", "light"]) {
  test(`findings drill-down and installation links stay usable in the static demo (${theme})`, async ({ page }, testInfo) => {
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.goto(url("/findings?lane=all"), { waitUntil: "networkidle" });
    await expect(page.getByRole("button", { name: "Low (0)", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: /undefined/ })).toHaveCount(0);
    const assets = page.locator('a[href*="/findings?q="]');
    expect(await assets.count()).toBeGreaterThan(0);
    for (const href of await assets.evaluateAll(links => links.map(link => link.getAttribute("href")))) {
      expect(href).toMatch(/^\/agent-bom\/demo\/findings\?q=/);
    }
    await expect(page.getByTestId("demo-nav-sign-in")).toHaveAttribute("href", "https://koda-ai-studio.github.io/agent-bom/getting-started/quickstart/");
    await expect(page.getByRole("link", { name: /sign in/i })).toHaveCount(0);
    await assets.first().click();
    await expect(page).toHaveURL(/\/agent-bom\/demo\/findings\?q=/);
    await expect(page.getByRole("table", { name: "Findings and supporting evidence" })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`findings-drilldown-${theme}.png`), fullPage: true });
  });
}
