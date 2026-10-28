#!/usr/bin/env node
/**
 * Record the read-only demo's API answers into `<out>/demo-data/*.json`.
 *
 * Crawls the static export (built with NEXT_PUBLIC_STATIC_DEMO=1) and answers
 * every demo-data read from the product-proof fixture routes — the same
 * labelled sample estate the README screenshots use — plus the PHP2Shell
 * advisory fixture and the journey answers derived from that estate
 * (static-demo-routes.mjs). Nothing is hand-written and nothing touches a
 * network.
 *
 *   node scripts/generate-static-demo-data.mjs --out out --base-path /agent-bom/demo
 */
import { chromium } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { FIXTURE_SCAN_ID, fixtureAuditEntries, fixtureFindings, fixtureGraph, installRoutes } from "./capture-product-proof.mjs";
import { CREATED_AT } from "./product-proof-fixtures.mjs";
import { staticDemoDataKey, staticDemoQueryKey } from "../lib/static-demo-key.mjs";
import { installStaticDemoRoutes } from "./static-demo-routes.mjs";
import { startStaticDemoServer } from "./static-demo-server.mjs";

const UI_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const PHP2SHELL_ID = "CVE-2026-109618";
// Keeps the published export small; a larger answer is left out and reported.
const MAX_RESPONSE_BYTES = 1_500_000;

/** Deep links the overview and guides use, crawled after every exported page. */
const DEEP_LINKS = [
  "/findings?lens=trust", `/advisories?id=${PHP2SHELL_ID}`, "/advisories?tab=declare",
  // The Investigation journey: each step reads its own evidence for the headline path.
  "/security-graph?step=impact", "/security-graph?step=owner", "/security-graph?step=fix", "/remediation?view=verification",
];
// Pages whose only purpose is a write (sign-in, starting a scan) are never part of a read-only demo.
const WRITE_ONLY_ROUTES = new Set(["/login", "/scan"]);

/** Every page the static export contains, as app routes (`index.html` → `/`). */
export async function exportedRoutes(outDir) {
  const routes = [];
  const walk = async (dir, prefix) => {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!entry.name.startsWith("_") && entry.name !== "demo-data") await walk(path.join(dir, entry.name), `${prefix}/${entry.name}`);
      } else if (entry.name.endsWith(".html") && !["404.html", "_not-found.html"].includes(entry.name)) {
        const name = entry.name.slice(0, -".html".length);
        routes.push(name === "index" ? prefix || "/" : `${prefix}/${name}`);
      }
    }
  };
  await walk(outDir, "");
  return routes.sort();
}

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
  const appRoute = (url) => {
    const pathname = new URL(url).pathname.slice(basePath.length) || "/";
    return pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  };
  const browser = await chromium.launch();
  const recorded = new Map();
  const missing = new Set();
  const incomplete = new Set();
  const unanswered = new Set();
  const redirects = new Map();
  const oversized = new Set();
  try {
    const apiPage = await browser.newPage();
    await installRoutes(apiPage);
    await installAdvisoryRoutes(apiPage);
    await apiPage.goto(`${server.origin}/`);
    // Every page, the overview included, answers from the one fixture estate so its counts reconcile.
    await installStaticDemoRoutes(apiPage, {
      graph: fixtureGraph, findings: fixtureFindings(), auditEntries: fixtureAuditEntries(), scanId: FIXTURE_SCAN_ID, tenantId: "default", snapshotAt: CREATED_AT,
    });

    const answer = async (apiPath) => {
      return apiPage.evaluate(async (url) => {
        const res = await fetch(url);
        return { status: res.status, body: await res.text() };
      }, apiPath);
    };

    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.route("**/demo-data/**", async (route) => {
      const apiPath = new URL(route.request().url()).searchParams.get("path") ?? "";
      // The UI asks for the exact-query file first, then the path file.
      const key = path.basename(new URL(route.request().url()).pathname, ".json");
      const exactQuery = key === staticDemoQueryKey(apiPath);
      if (!apiPath.startsWith("/") || (key !== staticDemoDataKey(apiPath) && !exactQuery)) return route.fulfill({ status: 404, body: "" });
      if (unanswered.has(key)) return route.fulfill({ status: 404, body: "" });
      if (!recorded.has(key)) {
        const { status, body } = await answer(apiPath);
        let json;
        try { json = status === 200 ? JSON.parse(body) : undefined; } catch { json = undefined; }
        if (json !== undefined && body.length > MAX_RESPONSE_BYTES) {
          oversized.add(apiPath.split("?")[0]);
          json = undefined;
        }
        if (json === undefined) {
          unanswered.add(key);
          if (!exactQuery) {
            missing.add(apiPath.split("?")[0]);
            incomplete.add(appRoute(page.url()));
          }
          return route.fulfill({ status: 404, body: "" });
        }
        recorded.set(key, JSON.stringify(json));
        await fs.writeFile(path.join(dataDir, `${key}.json`), recorded.get(key));
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: recorded.get(key) });
    });
    const routes = await exportedRoutes(outDir);
    for (const route of [...routes, ...DEEP_LINKS]) {
      await page.goto(`${server.origin}${basePath}${route}`, { waitUntil: "networkidle" });
      await page.waitForTimeout(400);
      const landed = appRoute(page.url());
      if (routes.includes(route) && landed !== route) redirects.set(route, landed);
    }
    // A redirecting page is in the demo only when the page it lands on is.
    const complete = (route) => !incomplete.has(route) && !WRITE_ONLY_ROUTES.has(route);
    const included = routes.filter((route) => complete(route) && (!redirects.has(route) || complete(redirects.get(route))));
    await fs.writeFile(path.join(dataDir, "routes.json"), JSON.stringify({
      schema_version: "static-demo-routes.v1",
      // The sample data is dated at this snapshot; the UI measures ages from it.
      snapshot_at: CREATED_AT,
      routes: included,
      excluded: routes.filter((route) => !included.includes(route)),
    }, null, 2));
    console.log(`static demo routes: ${included.length} with sample data, ${routes.length - included.length} shown as not in the demo`);
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

if (import.meta.url === `file://${process.argv[1]}`) main().catch((error) => {
  console.error(error);
  process.exit(1);
});
