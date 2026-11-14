import { readFileSync } from "node:fs";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

type Fixture = { first_page: { scan_id: string; pagination: { next_cursor: string } }; second_page: unknown };
const pages = JSON.parse(readFileSync(path.join(__dirname, "..", "tests", "fixtures", "agent-architecture.json"), "utf8")) as Fixture;

const SHOTS = process.env.ARCHITECTURE_SHOT_DIR;
const ROUTE = "/v1/graph/agent-architecture";

type Behaviour = { continuation?: "ok" | "stale" | "invalid" };

async function mockApi(page: Page, behaviour: Behaviour = {}) {
  const calls: string[] = [];
  let staleServed = false;
  await page.route("**/v1/**", route => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith("/v1/auth/")) return route.fulfill({ json: { authenticated: true, role: "analyst", tenant_id: "fixture", permissions: ["read"] } });
    if (url.pathname === ROUTE) {
      const cursor = url.searchParams.get("cursor");
      calls.push(cursor ?? "");
      if (!cursor) return route.fulfill({ json: pages.first_page });
      if (behaviour.continuation === "stale" && !staleServed) {
        staleServed = true;
        return route.fulfill({ status: 409, json: { detail: "Graph snapshot changed; restart the query from its first page." } });
      }
      if (behaviour.continuation === "invalid") return route.fulfill({ status: 422, json: { detail: "Invalid cursor for this query; restart from the first page." } });
      return route.fulfill({ json: pages.second_page });
    }
    if (/\/v1\/graph\/node\/[^/]+\/neighbors$/.test(url.pathname)) {
      const nodeId = decodeURIComponent(url.pathname.split("/")[4]!);
      return route.fulfill({ json: {
        node_id: nodeId, scan_id: pages.first_page.scan_id, found: true, direction: "out", limit: 100, total_neighbors: 1, truncated: false,
        neighbors: [{ id: "vuln:CVE-2026-0003", entity_type: "vulnerability", label: "CVE-2026-0003", severity: "critical" }],
        edges: [{ id: "e1", source: nodeId, target: "vuln:CVE-2026-0003", relationship: "vulnerable_to" }],
      } });
    }
    return route.fulfill({ status: 503, json: { detail: "Outside the architecture fixture" } });
  });
  return calls;
}

async function prepare(page: Page, theme: "light" | "dark", width: number) {
  await page.setViewportSize({ width, height: 1100 });
  await page.emulateMedia({ colorScheme: theme });
  await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
}

/** Nodes not wholly inside the canvas: the first frame must show the whole harness. */
/** Nodes the canvas leaves off screen must be exactly the ones it says are off screen. */
async function expectOffscreenDisclosed(page: Page) {
  await expect.poll(async () => {
    const clipped = await clippedNodes(page);
    const status = page.getByTestId("architecture-canvas").getByRole("status").filter({ hasText: /off screen/ });
    const said = await status.count() ? Number((await status.first().textContent())?.match(/(\d+) more/)?.[1] ?? -1) : 0;
    return clipped === said;
  }).toBe(true);
}

async function clippedNodes(page: Page): Promise<number> {
  return page.evaluate(() => {
    const frame = document.querySelector("[data-testid=architecture-canvas]")!.getBoundingClientRect();
    return [...document.querySelectorAll(".react-flow__node")].filter(node => {
      const rect = node.getBoundingClientRect();
      return rect.left < frame.left - 1 || rect.right > frame.right + 1 || rect.top < frame.top - 1 || rect.bottom > frame.bottom + 1;
    }).length;
  });
}

/** Connector paths that pass through a node box other than their own ends, in screen space. */
async function linesThroughNodes(page: Page): Promise<number> {
  return page.evaluate(() => {
    const nodes = [...document.querySelectorAll<HTMLElement>(".react-flow__node")].map(node => ({ id: node.dataset.id ?? "", rect: node.getBoundingClientRect() }));
    let hits = 0;
    for (const path of document.querySelectorAll<SVGPathElement>(".react-flow__edge-path")) {
      const edge = path.closest<HTMLElement>(".react-flow__edge")?.dataset.id ?? "";
      const matrix = path.getScreenCTM();
      if (!matrix) continue;
      for (const node of nodes) {
        if (edge.split("->").includes(node.id)) continue;
        for (let length = 0; length <= path.getTotalLength(); length += 2) {
          const point = new DOMPoint(path.getPointAtLength(length).x, path.getPointAtLength(length).y).matrixTransform(matrix);
          if (point.x > node.rect.left + 4 && point.x < node.rect.right - 4 && point.y > node.rect.top + 4 && point.y < node.rect.bottom - 4) { hits += 1; break; }
        }
      }
    }
    return hits;
  });
}

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`agent architecture reads in layers and as a flow in ${theme} at ${width}`, async ({ page }) => {
    await prepare(page, theme, width);
    await mockApi(page);
    await page.goto("/agents/architecture");
    await expect(page.getByRole("heading", { name: "Agent architecture", level: 1 })).toBeVisible();
    await expect(page.getByText("Observed runtime paths are not available yet", { exact: false })).toBeVisible();
    await expect(page.getByRole("button", { name: "Load more harnesses (2 of 3)" })).toBeVisible();
    if (width < 640) {
      await expect(page.locator(".react-flow")).toHaveCount(0);
      const layers = page.getByRole("region", { name: "Harness layers" });
      await expect(layers.getByRole("button", { name: /^supervisor, Orchestrator, entry, 1 finding on supervisor, worst critical/ })).toBeVisible();
      await expect(layers.getByText("1 unresolved route")).toBeVisible();
      if (SHOTS) await page.screenshot({ path: `${SHOTS}/architecture-layered-${theme}-${width}.png`, fullPage: true });
      await page.getByRole("button", { name: "Flow", exact: true }).click();
      await expect(page.getByRole("region", { name: "Harness flow steps" })).toBeVisible();
      if (SHOTS) await page.screenshot({ path: `${SHOTS}/architecture-flow-${theme}-${width}.png`, fullPage: true });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
      await page.getByRole("button", { name: /^supervisor, Orchestrator/ }).click();
    } else {
      const canvas = page.getByTestId("architecture-canvas");
      await expect(canvas.locator(".react-flow__node")).toHaveCount(9);
      await expect(canvas.locator(".react-flow__controls")).toBeVisible();
      await expectOffscreenDisclosed(page);
      await expect.poll(() => linesThroughNodes(page)).toBe(0);
      await expect(page.getByRole("button", { name: "1 finding on supervisor, worst critical. Open details" })).toHaveAttribute("data-severity", "critical");
      if (SHOTS) await page.screenshot({ path: `${SHOTS}/architecture-layered-${theme}-${width}.png`, fullPage: true });
      await page.getByRole("button", { name: "Flow", exact: true }).click();
      await expect(canvas).toHaveAttribute("data-layout", "flow");
      await expect(canvas.getByText("End", { exact: true })).toBeVisible();
      await expectOffscreenDisclosed(page);
      await expect.poll(() => linesThroughNodes(page)).toBe(0);
      if (SHOTS) await page.screenshot({ path: `${SHOTS}/architecture-flow-${theme}-${width}.png`, fullPage: true });
      const supervisor = canvas.locator(".react-flow__node", { has: page.getByText("supervisor", { exact: true }) });
      await supervisor.focus();
      await page.keyboard.press("Enter");
    }
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("link", { name: "Open CVE-2026-0003 in findings" })).toHaveAttribute("href", "/findings?cve=CVE-2026-0003");
    await expect(dialog.getByRole("link", { name: "Investigate in graph" })).toBeVisible();
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/architecture-detail-${theme}-${width}.png` });
  });
}

test("loads the next harnesses with the API cursor and restarts on a changed snapshot", async ({ page }) => {
  await prepare(page, "light", 1440);
  const calls = await mockApi(page, { continuation: "stale" });
  await page.goto("/agents/architecture");
  await page.getByRole("button", { name: "Load more harnesses (2 of 3)" }).click();
  await expect(page.getByText(/snapshot changed while paging/)).toBeVisible();
  expect(calls).toEqual(["", pages.first_page.pagination.next_cursor, ""]);
  await page.getByRole("button", { name: "Load more harnesses (2 of 3)" }).click();
  await expect(page.getByRole("navigation", { name: "Harnesses" }).getByRole("button", { name: /^crew/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Load more harnesses/ })).toHaveCount(0);
});

test("reports a rejected cursor and starts over on request", async ({ page }) => {
  await prepare(page, "dark", 1440);
  const calls = await mockApi(page, { continuation: "invalid" });
  await page.goto("/agents/architecture");
  await page.getByRole("button", { name: "Load more harnesses (2 of 3)" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Invalid cursor" })).toBeVisible();
  await page.getByRole("button", { name: "Start over" }).click();
  await expect(page.getByText(/Invalid cursor/)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Load more harnesses (2 of 3)" })).toBeVisible();
  expect(calls.at(-1)).toBe("");
});
