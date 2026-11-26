import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect, type Page } from "@playwright/test";

// The quickstart sample's scope overview: six recorded scopes and their aggregate links.
const rollup = JSON.parse(readFileSync(join(__dirname, "fixtures/quickstart-scope-rollup.json"), "utf8")) as {
  top_level: { id: string; label: string; entity_type: string }[];
};
const stamp = "2026-11-05T00:00:00Z";

async function serve(page: Page, theme: string) {
  await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
  const nodes = rollup.top_level.map(item => ({ id: item.id, label: item.label, entity_type: item.entity_type, severity: "none", attributes: {}, data_sources: [] }));
  await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", r => {
    const path = new URL(r.request().url()).pathname;
    if (path === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (path === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "quickstart", created_at: stamp, snapshot_kind: "scan", node_count: 32, edge_count: 49 }] });
    if (path === "/v1/graph/rollup") return r.fulfill({ json: rollup });
    const graph = { scan_id: "quickstart", tenant_id: "fixture", created_at: stamp, nodes, edges: [], attack_paths: [], interaction_risks: [],
      stats: { total_nodes: 32, total_edges: 49, severity_counts: {} } };
    if (path === "/v1/graph/attack-paths") return r.fulfill({ json: { ...graph, nodes: [], pagination: { total: 0, offset: 0, limit: 75, has_more: false } } });
    if (path === "/v1/graph") return r.fulfill({ json: { ...graph, pagination: { total: 32, offset: 0, limit: 100, returned: nodes.length, has_more: false } } });
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
}

/** Scope cards inside the canvas frame and the smallest card text as drawn on screen. */
async function frame(page: Page) {
  return page.locator(".react-flow").evaluate(canvas => {
    const box = canvas.getBoundingClientRect();
    const zoom = new DOMMatrixReadOnly(getComputedStyle(canvas.querySelector(".react-flow__viewport")!).transform).a;
    const nodes = [...canvas.querySelectorAll<HTMLElement>(".react-flow__node")];
    const framed = nodes.filter(node => {
      const r = node.getBoundingClientRect();
      return r.width > 0 && r.left >= box.left - 1 && r.right <= box.right + 1 && r.top >= box.top - 1 && r.bottom <= box.bottom + 1;
    }).length;
    let smallest = Infinity;
    for (const element of canvas.querySelectorAll<HTMLElement>(".react-flow__node *")) {
      if (element.closest(".sr-only") || ![...element.childNodes].some(child => child.nodeType === 3 && child.textContent?.trim())) continue;
      smallest = Math.min(smallest, parseFloat(getComputedStyle(element).fontSize) * zoom);
    }
    return { total: nodes.length, framed, smallest };
  });
}

for (const theme of ["light", "dark"]) {
  for (const viewport of [{ width: 390, height: 844 }, { width: 1440, height: 900 }]) {
    test(`shared quickstart scopes open readable connections with full navigation in ${theme} ${viewport.width}`, async ({ page }, info) => {
      await page.setViewportSize(viewport);
      await serve(page, theme);
      await page.goto("/security-graph?scan=quickstart&lens=lineage");
      const overview = page.getByTestId("graph-scope-overview");
      await expect(overview).toBeVisible();
      await expect(page.locator(".react-flow__node")).toHaveCount(4);
      await expect(overview).toContainText("9 of 9 loaded relationships for this scope");
      await expect(page.getByLabel("Connection scope").locator("option")).toHaveCount(6);
      await expect.poll(async () => (await frame(page)).framed, { timeout: 10_000 }).toBe(4);
      const view = await frame(page);
      expect(view.smallest).toBeGreaterThanOrEqual(11);
      const summaries = page.locator(".graph-aggregate-label");
      await expect(summaries).toHaveCount(2);
      await expect(summaries).toHaveText(["4 relationships", "4 relationships"]);
      await expect.poll(() => summaries.evaluateAll(labels => {
        const boxes = labels.map(label => label.getBoundingClientRect());
        const overlaps = (a: DOMRect, b: DOMRect) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
        const captions = [...document.querySelectorAll("[data-graph-entity] > *")].map(node => node.getBoundingClientRect());
        return boxes.flatMap((box, index) => [
          ...boxes.slice(index + 1).filter(other => overlaps(box, other)).map(() => "count labels overlap"),
          ...captions.filter(other => overlaps(box, other)).map(() => "count label overlaps a card"),
        ]);
      }), { timeout: 3000 }).toEqual([]);
      await expect(page.getByTestId("graph-in-view")).toHaveCount(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
      await page.screenshot({ path: info.outputPath(`scope-${theme}-${viewport.width}.png`), fullPage: true });
      await overview.getByRole("button", { name: "Browse all 6 nodes and scopes" }).click();
      const directory = page.getByTestId("graph-rollup-decision-surface");
      await expect(directory).toBeVisible();
      await directory.getByRole("button", { name: "All 6", exact: true }).click();
      await expect(directory.locator("article")).toHaveCount(6);
      for (const item of rollup.top_level) await expect(directory.locator("article p").filter({ hasText: item.label }).first()).toBeVisible();
      await overview.getByRole("button", { name: "Show connections" }).click();
      await expect(page.locator(".react-flow__node")).toHaveCount(4);
    });
  }
}
