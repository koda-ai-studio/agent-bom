#!/usr/bin/env node
/**
 * Record the read-only demo's API answers into `<out>/demo-data/*.json`.
 *
 * Crawls the static export (built with NEXT_PUBLIC_STATIC_DEMO=1) and answers
 * every demo-data read from the product-proof fixture routes — the same
 * labelled sample estate the README screenshots use — plus the PHP2Shell
 * advisory fixture. Nothing is hand-written and nothing touches a network.
 *
 *   node scripts/generate-static-demo-data.mjs --out out --base-path /agent-bom/demo
 */
import { chromium } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { installRoutes, overviewProof } from "./capture-product-proof.mjs";
import { staticDemoDataKey } from "../lib/static-demo-key.mjs";
import { startStaticDemoServer } from "./static-demo-server.mjs";

const UI_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const PHP2SHELL_ID = "CVE-2026-109618";
// Keeps the published export small; a larger answer is left out and reported.
const MAX_RESPONSE_BYTES = 1_500_000;

/** Every page in the demo navigation, plus deep links the overview and guides use. */
export const DEMO_CRAWL = [
  "/", "/security-graph", "/graph", "/findings", "/findings?lens=trust", "/advisories",
  `/advisories?id=${PHP2SHELL_ID}`, "/advisories?tab=declare", "/remediation", "/inventory", "/agents", "/skills",
  "/manifest", "/fleet", "/compliance", "/governance", "/drift", "/audit", "/blueprints", "/runtime",
  "/live-activity", "/cwpp", "/traces", "/identity", "/cost", "/jobs", "/activity", "/integrations",
  "/self-posture", "/registry", "/vulns", "/insights", "/mesh", "/context", "/threat-intel", "/reports",
];

function arg(name, fallback) {
  const index = process.argv.indexOf(name);
  return index > 0 ? process.argv[index + 1] : fallback;
}

async function installAdvisoryRoutes(page) {
  const affected = JSON.parse(await fs.readFile(path.join(UI_ROOT, "tests/fixtures/php2shell-affected.json"), "utf8"));
  await page.route("**/v1/intel/advisories/*/affected**", (route) => route.fulfill({ json: affected }));
  await page.route("**/v1/intel/operator-advisories", (route) => route.fulfill({ json: {
    advisories: [{
      id: PHP2SHELL_ID, aliases: ["CVE-2026-109619"], summary: affected.advisory.summary, severity: "critical",
      references: [], affected: [{ cpe_product: "php:php", ranges: [], versions: [] }], updated_at: "2026-10-23T09:00:00+00:00",
    }],
    provenance: "operator_advisory",
    rematch: { last_run: "2026-10-24T01:00:00+00:00" },
  } }));
}

async function main() {
  const outDir = path.resolve(arg("--out", path.join(UI_ROOT, "out")));
  const basePath = arg("--base-path", "/agent-bom/demo");
  const dataDir = path.join(outDir, "demo-data");
  await fs.rm(dataDir, { recursive: true, force: true });
  await fs.mkdir(dataDir, { recursive: true });

  const server = await startStaticDemoServer(outDir, basePath);
  const browser = await chromium.launch();
  const recorded = new Map();
  const missing = new Set();
  const oversized = new Set();
  try {
    const apiPage = await browser.newPage();
    await installRoutes(apiPage);
    await installAdvisoryRoutes(apiPage);
    await apiPage.goto(`${server.origin}/`);

    const answer = async (apiPath, onOverview) => {
      const proof = overviewProof.responses[apiPath.split("?")[0]];
      if (onOverview && proof) return { status: 200, body: JSON.stringify(proof) };
      return apiPage.evaluate(async (url) => {
        const res = await fetch(url);
        return { status: res.status, body: await res.text() };
      }, apiPath);
    };

    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.route("**/demo-data/**", async (route) => {
      const apiPath = new URL(route.request().url()).searchParams.get("path") ?? "";
      const key = staticDemoDataKey(apiPath);
      if (!apiPath.startsWith("/")) return route.fulfill({ status: 404, body: "" });
      if (!recorded.has(key)) {
        const onOverview = new URL(page.url()).pathname === `${basePath}` || new URL(page.url()).pathname === `${basePath}/`;
        const { status, body } = await answer(apiPath, onOverview);
        let json;
        try { json = status === 200 ? JSON.parse(body) : undefined; } catch { json = undefined; }
        if (json !== undefined && body.length > MAX_RESPONSE_BYTES) {
          oversized.add(apiPath.split("?")[0]);
          json = undefined;
        }
        if (json === undefined) {
          missing.add(apiPath.split("?")[0]);
          return route.fulfill({ status: 404, body: "" });
        }
        recorded.set(key, JSON.stringify(json));
        await fs.writeFile(path.join(dataDir, `${key}.json`), recorded.get(key));
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: recorded.get(key) });
    });
    for (const route of DEMO_CRAWL) {
      await page.goto(`${server.origin}${basePath}${route}`, { waitUntil: "networkidle" });
      await page.waitForTimeout(400);
    }
  } finally {
    await browser.close();
    await server.close();
  }
  const bytes = [...recorded.values()].reduce((sum, body) => sum + body.length, 0);
  console.log(`static demo data: ${recorded.size} responses, ${(bytes / 1024).toFixed(0)} KiB -> ${path.relative(process.cwd(), dataDir)}`);
  if (missing.size) console.log(`no sample data (views show their empty/error state): ${[...missing].sort().join(", ")}`);
  if (oversized.size) console.log(`left out, over ${MAX_RESPONSE_BYTES} bytes: ${[...oversized].sort().join(", ")}`);
  if (recorded.size === 0) throw new Error("static demo recorded no responses");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
