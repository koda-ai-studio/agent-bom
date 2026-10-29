#!/usr/bin/env node
/**
 * Click through the built read-only demo with no API behind it and fail on any
 * request that leaves the Pages origin or base path, a missing banner, sideways
 * page scroll, or a write that reaches the network.
 *
 *   node scripts/verify-static-demo.mjs --out out --base-path /agent-bom/demo [--screenshots dir]
 *   VERIFY_PLANT_REQUEST=<url> … plants one off-origin fetch to prove the check fails.
 */
import { chromium } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { exportedRoutes } from "./generate-static-demo-data.mjs";
import { startStaticDemoServer } from "./static-demo-server.mjs";

// Sample data is dated at its snapshot; wall-clock ages would read months or years old.
const WALL_CLOCK_AGE = /\b\d+\s*(months?|years?|mo|yr)\s+ago\b|\b[1-9]\d{2,}\s*(d|days?)\s+ago\b|overdue by \d+ (months?|years?)/i;
const ERROR_TEXT = /no sample data in the read-only demo|something went wrong|failed to load|could not be loaded|network request failed|application error/i;

// [name, route, expected text, text that must not appear]
const PAGES = [
  ["overview", "/", "Overview"],
  ["investigation", "/security-graph", null],
  ["investigation-impact", "/security-graph?step=impact", /\d+ assets? exposed to this finding/, /Impact evidence is unavailable/],
  ["investigation-owner", "/security-graph?step=owner", /Owner \/ team\s*data-platform/, /Ownership is unavailable|No finding record for this path/],
  ["investigation-verify", "/remediation?view=verification", /Awaiting re-verification/, /no sample data/],
  ["findings", "/findings", /Vulnerabilities\s*\d+/, null],
  ["audit", "/audit", /completed|denied|issued/, /Not recorded/],
  ["advisories-php2shell", "/advisories?id=CVE-2026-109618", null],
  ["inventory", "/inventory", null],
  ["remediation", "/remediation", null],
];
const VIEWPORTS = [{ width: 1440, height: 900 }, { width: 390, height: 844 }];

function arg(name, fallback) {
  const index = process.argv.indexOf(name);
  return index > 0 ? process.argv[index + 1] : fallback;
}

async function main() {
  const outDir = path.resolve(arg("--out", "out"));
  const basePath = arg("--base-path", "/agent-bom/demo");
  const shots = arg("--screenshots");
  if (shots) await fs.mkdir(shots, { recursive: true });
  const server = await startStaticDemoServer(outDir, basePath);
  const browser = await chromium.launch();
  const problems = [];
  let requests = 0;
  try {
    for (const viewport of VIEWPORTS) for (const theme of ["light", "dark"]) {
      const context = await browser.newContext({ viewport, colorScheme: theme });
      const page = await context.newPage();
      await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
      if (process.env.VERIFY_PLANT_REQUEST) {
        await page.addInitScript((url) => { void fetch(url).catch(() => undefined); }, process.env.VERIFY_PLANT_REQUEST);
      }
      const label = `${viewport.width}/${theme}`;
      page.on("request", (request) => {
        requests += 1;
        const url = new URL(request.url());
        if (url.protocol === "data:" || url.protocol === "blob:") return;
        const baseRsc = url.pathname === `${basePath}.txt`;
        if (url.origin !== server.origin || !baseRsc && !url.pathname.startsWith(`${basePath}/`) && url.pathname !== basePath) {
          problems.push(`${label}: request outside the demo origin/base path: ${request.method()} ${request.url()}`);
        }
      });
      page.on("response", (response) => {
        const url = new URL(response.url());
        // Exact-query files are optional; the path file behind them must exist.
        if (url.pathname.includes("/demo-data/") && !url.pathname.includes("__q") && response.status() !== 200) {
          problems.push(`${label}: no sample data for ${url.searchParams.get("path")} on ${new URL(page.url()).pathname}`);
        }
      });
      for (const [name, route, expected, forbidden] of PAGES) {
        await page.goto(`${server.origin}${basePath}${route}`, { waitUntil: "networkidle" });
        await page.waitForTimeout(600);
        const text = await page.locator("#main-content").innerText().catch(() => "");
        if (expected instanceof RegExp && !expected.test(text)) problems.push(`${label} ${name}: expected ${expected} in the page`);
        if (forbidden && forbidden.test(text)) problems.push(`${label} ${name}: ${text.match(forbidden)[0]}`);
        if (!(await page.getByTestId("static-demo-banner").isVisible())) problems.push(`${label} ${name}: demo banner not visible`);
        const theme_ = await page.locator("html").getAttribute("data-theme");
        if (theme_ !== theme) problems.push(`${label} ${name}: theme ${theme_} != ${theme}`);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        if (overflow > 0) problems.push(`${label} ${name}: horizontal overflow ${overflow}px`);
        if (shots) await page.screenshot({ path: path.join(shots, `${name}-${theme}-${viewport.width}.png`) });
      }
      const demoRoutes = new Set(JSON.parse(await fs.readFile(path.join(outDir, "demo-data", "routes.json"), "utf8")).routes);
      const unavailable = (await exportedRoutes(outDir)).filter((route) => !demoRoutes.has(route));
      if (unavailable.length) {
        await page.goto(`${server.origin}${basePath}${unavailable[0]}`, { waitUntil: "networkidle" });
        if (!(await page.getByTestId("static-demo-unavailable").isVisible())) problems.push(`${label}: not-in-demo panel missing on ${unavailable[0]}`);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        if (overflow > 0) problems.push(`${label} not-in-demo: horizontal overflow ${overflow}px`);
        if (shots) await page.screenshot({ path: path.join(shots, `not-in-demo-${theme}-${viewport.width}.png`) });
      }
      if (viewport.width === 1440 && theme === "light") {
        // Every exported route: recorded pages show data, the rest show the panel, none an error.
        for (const route of await exportedRoutes(outDir)) {
          await page.goto(`${server.origin}${basePath}${route}`, { waitUntil: "networkidle" });
          await page.waitForTimeout(300);
          const panel = await page.getByTestId("static-demo-unavailable").isVisible();
          const text = await page.locator("#main-content").innerText().catch(() => "");
          if (demoRoutes.has(route) === panel) problems.push(`${route}: ${panel ? "panel shown on a recorded page" : "unrecorded page rendered without the panel"}`);
          if (ERROR_TEXT.test(text)) problems.push(`${route}: error state: ${text.match(ERROR_TEXT)[0]}`);
          if (WALL_CLOCK_AGE.test(text)) problems.push(`${route}: wall-clock age: ${text.match(WALL_CLOCK_AGE)[0]}`);
          if (!(await page.getByTestId("static-demo-banner").isVisible())) problems.push(`${route}: demo banner not visible`);
          const hidden = await page.getByRole("navigation").getByRole("link").evaluateAll((links, base) => links
            .map((link) => new URL(link.href).pathname.slice(base.length) || "/"), basePath);
          for (const href of hidden) if (!demoRoutes.has(href.replace(/\/+$/, "") || "/")) problems.push(`${route}: nav links to ${href}, which is not in the demo`);
        }
      }
      if (viewport.width === 1440 && theme === "light") {
        // Overview severity tiles and the Findings lanes read the same sample estate.
        await page.goto(`${server.origin}${basePath}/`, { waitUntil: "networkidle" });
        await page.waitForTimeout(600);
        const tiles = await page.getByTestId("overview-severity-issue-strip").evaluate((strip) => Object.fromEntries(
          [...strip.querySelectorAll("a, button")].map((tile) => [...tile.querySelectorAll("p")].map((p) => p.textContent?.trim() ?? ""))
            .filter((cells) => ["Critical", "High", "Medium", "Low"].includes(cells[0] ?? "")).map((cells) => [cells[0].toLowerCase(), Number(cells[1].replace(/,/g, ""))])));
        await page.goto(`${server.origin}${basePath}/findings`, { waitUntil: "networkidle" });
        await page.waitForTimeout(600);
        const findingsText = await page.locator("#main-content").innerText();
        const laneTotal = Number(/All findings\s*([\d,]+)/.exec(findingsText)?.[1]?.replace(/,/g, "") ?? Number.NaN);
        const pills = Object.fromEntries(["Critical", "High", "Medium", "Low"].map((band) => [band.toLowerCase(), Number(new RegExp(`${band} \\((\\d+)\\)`).exec(findingsText)?.[1] ?? Number.NaN)]));
        const tileTotal = Object.values(tiles).reduce((sum, value) => sum + value, 0);
        if (Object.keys(tiles).length !== 4 || Number.isNaN(laneTotal)) problems.push(`reconciliation: could not read overview tiles ${JSON.stringify(tiles)} or lane total ${laneTotal}`);
        else if (tileTotal !== laneTotal) problems.push(`reconciliation: overview tiles sum to ${tileTotal}, findings lanes total ${laneTotal}`);
        for (const band of Object.keys(tiles)) if (!Number.isNaN(pills[band]) && pills[band] !== tiles[band]) problems.push(`reconciliation: overview ${band} ${tiles[band]} != findings ${band} ${pills[band]}`);
      }
      if (viewport.width === 1440) {
        await page.goto(`${server.origin}${basePath}/`, { waitUntil: "networkidle" });
        await page.getByRole("navigation").getByRole("link", { name: /^Findings/ }).first().click();
        await page.waitForURL((url) => url.pathname === `${basePath}/findings`);
        await page.getByRole("heading", { name: "Findings", exact: true }).waitFor();
        await page.goto(`${server.origin}${basePath}/advisories?tab=declare`, { waitUntil: "networkidle" });
        await page.getByLabel("Advisory ID").fill("CVE-2026-109618");
        await page.getByLabel("Summary").fill("php2shell");
        await page.getByRole("radio", { name: "CPE product" }).check();
        await page.getByLabel("CPE product (vendor:product)").fill("php:php");
        await page.getByLabel("Introduced").fill("8.3.0");
        await page.getByLabel("Fixed").fill("8.3.36");
        await page.getByRole("button", { name: "Declare advisory" }).click();
        const refusal = page.getByRole("alert").filter({ hasText: "read-only demo" });
        try {
          await refusal.first().waitFor({ timeout: 5_000 });
        } catch {
          problems.push(`${label}: declaring an advisory did not show the read-only refusal`);
        }
        if (shots) await page.screenshot({ path: path.join(shots, `write-refused-${theme}-${viewport.width}.png`) });
      }
      await context.close();
    }
  } finally {
    await browser.close();
    await server.close();
  }
  console.log(`static demo verify: ${requests} requests, ${problems.length} problem(s)`);
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(problems.length ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
