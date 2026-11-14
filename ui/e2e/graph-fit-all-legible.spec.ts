import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect, type Page } from "@playwright/test";

type Graph = { nodes: { id: string; label: string }[]; edges: { id: string; source: string; target: string }[] };
/** `FIT_ALL_FIXTURE` adds graphs exported from a local estate (`{ name: { nodes, edges } }`) to the same checks. */
const extra = process.env.FIT_ALL_FIXTURE ? JSON.parse(readFileSync(process.env.FIT_ALL_FIXTURE, "utf8")) as Record<string, Graph> : {};
const fixtures = { ...JSON.parse(readFileSync(join(__dirname, "fixtures/k8s-projection.json"), "utf8")) as Record<string, Graph>, ...extra };
const SCENARIOS = ["withFindings", "clusterEstate", ...Object.keys(extra)];
const stamp = "2026-11-05T00:00:00Z";
const VIEWPORTS = [{ width: 1440, height: 900 }, { width: 390, height: 844 }];
/** Set to a directory to keep a screenshot of every Fit all frame. */
const SHOTS = process.env.FIT_ALL_SHOTS_DIR;

async function serve(page: Page, graph: Graph, theme: string) {
  await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
  const body = { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, ...graph, attack_paths: [], interaction_risks: [], stats: { total_nodes: graph.nodes.length, total_edges: graph.edges.length, severity_counts: {} } };
  await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", r => {
    const path = new URL(r.request().url()).pathname;
    if (path === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (path === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "snapshot", created_at: stamp, snapshot_kind: "scan", node_count: graph.nodes.length, edge_count: graph.edges.length }] });
    if (path === "/v1/graph") return r.fulfill({ json: { ...body, pagination: { total: graph.nodes.length, offset: 0, limit: 100, returned: graph.nodes.length, has_more: false } } });
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
}

async function settle(page: Page) {
  let previous = "", stable = 0;
  await expect.poll(async () => {
    const current = await page.locator(".react-flow__viewport").evaluate(element => getComputedStyle(element).transform);
    stable = current === previous ? stable + 1 : 0;
    previous = current;
    return stable;
  }, { intervals: [100], timeout: 10_000 }).toBeGreaterThanOrEqual(4);
}

async function open(page: Page) {
  await page.goto("/security-graph?scan=snapshot&lens=estate&rollup=0");
  const graphTab = page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true });
  await expect(page.locator(".react-flow__node").or(graphTab).first()).toBeVisible();
  if (await graphTab.isVisible()) await graphTab.click();
  await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
  await settle(page);
}

/** Card text under 11px on screen, for every card the reader can see. */
async function undersizedText(page: Page) {
  return page.locator(".react-flow").evaluate(canvas => {
    const frame = canvas.getBoundingClientRect();
    const zoom = new DOMMatrixReadOnly(getComputedStyle(canvas.querySelector(".react-flow__viewport")!).transform).a;
    const small: string[] = [];
    let visible = 0;
    for (const node of canvas.querySelectorAll<HTMLElement>(".react-flow__node")) {
      const rect = node.getBoundingClientRect();
      if (!(rect.width > 0 && rect.right > frame.left && rect.left < frame.right && rect.bottom > frame.top && rect.top < frame.bottom)) continue;
      visible++;
      for (const element of node.querySelectorAll<HTMLElement>("*")) {
        if (element.closest(".sr-only") || ![...element.childNodes].some(child => child.nodeType === 3 && child.textContent?.trim())) continue;
        const size = parseFloat(getComputedStyle(element).fontSize) * zoom;
        if (size < 10.95) small.push(`${size.toFixed(1)}px ${element.tagName.toLowerCase()}[${element.getAttribute("data-testid") ?? element.className}] ${element.textContent?.trim().slice(0, 24)}`);
      }
    }
    return { zoom, visible, small };
  });
}

for (const theme of ["light", "dark"]) for (const viewport of VIEWPORTS) for (const scenario of SCENARIOS) {
  test(`Fit all keeps ${scenario} card text at 11px or more in ${theme} ${viewport.width}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await serve(page, fixtures[scenario]!, theme);
    await open(page);
    await page.getByRole("button", { name: "fit view" }).click();
    await settle(page);
    const view = await undersizedText(page);
    if (SHOTS) await page.screenshot({ path: join(SHOTS, `fit-all-${scenario}-${theme}-${viewport.width}.png`) });
    expect(view.visible).toBeGreaterThan(0);
    expect(view.small).toEqual([]);
    const fullMap = page.getByRole("button", { name: /^Show full map/ });
    if (await fullMap.isVisible()) {
      await fullMap.click();
      await settle(page);
    }
    for (const control of [page.getByRole("button", { name: "Fit all", exact: true }), page.getByRole("button", { name: "fit view" })]) {
      if (!(await control.isVisible())) continue;
      await control.click();
      await settle(page);
      const full = await undersizedText(page);
      expect(full.visible).toBeGreaterThan(0);
      expect(full.small).toEqual([]);
    }
    if (SHOTS) await page.screenshot({ path: join(SHOTS, `fit-all-full-map-${scenario}-${theme}-${viewport.width}.png`) });
  });
}
