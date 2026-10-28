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
const nodesOutsideCanvas = (page: Page) => page.locator(".react-flow").first().evaluate((flow) => {
  const box = flow.getBoundingClientRect();
  return [...flow.querySelectorAll(".react-flow__node")].filter((node) => {
    const rect = node.getBoundingClientRect();
    return rect.top < box.top || rect.bottom > box.bottom || rect.left < box.left || rect.right > box.right;
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
