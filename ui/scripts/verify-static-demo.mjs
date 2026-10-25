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

import { startStaticDemoServer } from "./static-demo-server.mjs";

const PAGES = [
  ["overview", "/", "Overview"],
  ["investigation", "/security-graph", null],
  ["findings", "/findings", null],
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
        if (url.origin !== server.origin || !url.pathname.startsWith(`${basePath}/`) && url.pathname !== basePath) {
          problems.push(`${label}: request outside the demo origin/base path: ${request.method()} ${request.url()}`);
        }
      });
      page.on("response", (response) => {
        const url = new URL(response.url());
        if (url.pathname.includes("/demo-data/") && response.status() !== 200) {
          problems.push(`${label}: no sample data for ${url.searchParams.get("path")} on ${new URL(page.url()).pathname}`);
        }
      });
      for (const [name, route] of PAGES) {
        await page.goto(`${server.origin}${basePath}${route}`, { waitUntil: "networkidle" });
        await page.waitForTimeout(600);
        if (!(await page.getByTestId("static-demo-banner").isVisible())) problems.push(`${label} ${name}: demo banner not visible`);
        const theme_ = await page.locator("html").getAttribute("data-theme");
        if (theme_ !== theme) problems.push(`${label} ${name}: theme ${theme_} != ${theme}`);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        if (overflow > 0) problems.push(`${label} ${name}: horizontal overflow ${overflow}px`);
        if (shots) await page.screenshot({ path: path.join(shots, `${name}-${theme}-${viewport.width}.png`) });
      }
      if (viewport.width === 1440) {
        await page.goto(`${server.origin}${basePath}/`, { waitUntil: "networkidle" });
        await page.getByRole("navigation").getByRole("link", { name: /^Findings/ }).first().click();
        await page.waitForURL(`**${basePath}/findings`);
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
