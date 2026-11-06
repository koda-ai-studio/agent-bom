import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect, type Page } from "@playwright/test";

type Graph = { nodes: { id: string; label: string }[]; edges: { id: string; source: string; target: string }[] };
const fixtures = JSON.parse(readFileSync(join(__dirname, "fixtures/k8s-projection.json"), "utf8")) as Record<"projectScan" | "demoInventory" | "clusterEstate" | "snapshot", Graph>;
const stamp = "2026-11-05T00:00:00Z";
const VIEWPORTS = [{ width: 1440, height: 900 }, { width: 390, height: 844 }];

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

async function open(page: Page, query = "") {
  await page.goto(`/security-graph?scan=snapshot&lens=estate&rollup=0${query}`);
  const graphTab = page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true });
  await expect(page.locator(".react-flow__node").or(graphTab).first()).toBeVisible();
  if (await graphTab.isVisible()) await graphTab.click();
  await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
  let previous = "", stable = 0;
  await expect.poll(async () => {
    const current = await page.locator(".react-flow__viewport").evaluate(element => getComputedStyle(element).transform);
    stable = current === previous ? stable + 1 : 0;
    previous = current;
    return stable;
  }, { intervals: [100], timeout: 10_000 }).toBeGreaterThanOrEqual(4);
}

/** Every piece of text on every card the reader can see, at the size it is actually drawn. */
async function firstFrame(page: Page) {
  return page.locator(".react-flow").evaluate(canvas => {
    const frame = canvas.getBoundingClientRect();
    const zoom = new DOMMatrixReadOnly(getComputedStyle(canvas.querySelector(".react-flow__viewport")!).transform).a;
    const nodes = [...canvas.querySelectorAll<HTMLElement>(".react-flow__node")];
    const visible = (r: DOMRect) => r.width > 0 && r.right > frame.left && r.left < frame.right && r.bottom > frame.top && r.top < frame.bottom;
    const inFrame = (r: DOMRect) => r.width > 0 && r.left >= frame.left - 1 && r.right <= frame.right + 1 && r.top >= frame.top - 1 && r.bottom <= frame.bottom + 1;
    const undersized: string[] = [];
    const boxes: { id: string; left: number; right: number; top: number; bottom: number }[] = [];
    let framed = 0;
    for (const node of nodes) {
      const card = node.querySelector<HTMLElement>("[data-graph-entity], [data-testid='summary-node']") ?? node;
      const rect = card.getBoundingClientRect();
      if (inFrame(rect)) framed++;
      if (!visible(rect)) continue;
      const parts = [...(card.matches("[data-graph-entity]") ? card.children : [card])].filter(child => { const s = getComputedStyle(child); return s.display !== "none" && s.visibility !== "hidden"; }).map(child => child.getBoundingClientRect()).filter(r => r.width && r.height);
      boxes.push({ id: node.getAttribute("data-id")!, left: Math.min(...parts.map(r => r.left)), right: Math.max(...parts.map(r => r.right)), top: Math.min(...parts.map(r => r.top)), bottom: Math.max(...parts.map(r => r.bottom)) });
      for (const element of card.querySelectorAll<HTMLElement>("*")) {
        if (element.closest(".sr-only") || ![...element.childNodes].some(child => child.nodeType === 3 && child.textContent?.trim())) continue;
        const size = parseFloat(getComputedStyle(element).fontSize) * zoom;
        if (size < 11.95) undersized.push(`${size.toFixed(1)}px ${element.textContent?.trim().slice(0, 24)}`);
      }
    }
    const overlaps = boxes.flatMap((a, i) => boxes.slice(i + 1).filter(b => a.left < b.right - 1 && a.right > b.left + 1 && a.top < b.bottom - 1 && a.bottom > b.top + 1).map(b => `${a.id} overlaps ${b.id}`));
    return { zoom, framed, total: nodes.length, undersized, overlaps };
  });
}

for (const theme of ["light", "dark"]) for (const viewport of VIEWPORTS) {
  const size = `${theme} ${viewport.width}`;
  for (const scenario of ["projectScan", "demoInventory"] as const) {
    test(`${scenario} preview opens with no overlap and no text under 12px in ${size}`, async ({ page }, info) => {
      await page.setViewportSize(viewport);
      await serve(page, fixtures[scenario], theme);
      await open(page);
      await expect(page.getByRole("combobox", { name: "Investigation flow" }).locator("option:checked")).toHaveText("Automatic · connection preview");
      const view = await firstFrame(page);
      expect(view.overlaps).toEqual([]);
      expect(view.undersized).toEqual([]);
      expect(view.framed).toBeGreaterThanOrEqual(viewport.width < 640 ? 1 : view.total);
      await page.screenshot({ path: info.outputPath(`preview-${scenario}-${theme}-${viewport.width}.png`) });
    });

    test(`${scenario} full map opens on a readable part and says how much is in view in ${size}`, async ({ page }, info) => {
      await page.setViewportSize(viewport);
      await serve(page, fixtures[scenario], theme);
      await open(page, "&map_view=full");
      const view = await firstFrame(page);
      expect(view.overlaps).toEqual([]);
      expect(view.undersized).toEqual([]);
      expect(view.framed).toBeGreaterThanOrEqual(viewport.width < 640 ? 1 : 6);
      const hint = page.getByTestId("graph-in-view");
      await expect(hint).toContainText(/Showing \d+ of \d+ nodes/);
      await expect(hint).toContainText("Fit all");
      await page.screenshot({ path: info.outputPath(`full-${scenario}-${theme}-${viewport.width}.png`) });
    });
  }
}

test("a phone reaches graph content on its first screen", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[1]!);
  await serve(page, fixtures.projectScan, "light");
  await page.goto("/security-graph?scan=snapshot&lens=estate&rollup=0");
  const list = page.getByTestId("graph-path-list");
  await expect(list).toBeVisible();
  const row = await list.getByRole("button").first().boundingBox();
  expect(row!.y + row!.height).toBeLessThanOrEqual(VIEWPORTS[1]!.height);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
});

test("an operator's zoom still chooses the summary renderer on a full map", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[0]!);
  await serve(page, fixtures.projectScan, "light");
  await open(page, "&map_view=full");
  await page.getByRole("button", { name: /zoom out/i }).click();
  await expect(page.getByTestId("summary-node").first()).toBeAttached();
});

test("captions sit on a plate so a passing edge cannot run through their text", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[0]!);
  await serve(page, fixtures.snapshot, "light");
  await open(page);
  const plates = page.locator("[data-graph-entity] [data-graph-caption]");
  await expect(plates.first()).toBeVisible();
  expect(await plates.evaluateAll(items => items.every(item => getComputedStyle(item).backgroundColor !== "rgba(0, 0, 0, 0)"))).toBe(true);
});

test("a flow at the node limit routes its steps around the cards in view", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[0]!);
  await serve(page, fixtures.clusterEstate, "light");
  await open(page, "&map_view=full&flow=exposure");
  const crossings = await page.locator(".react-flow").evaluate(canvas => {
    const cards = [...canvas.querySelectorAll(".react-flow__node .graph-entity-glyph")].map(glyph => ({ id: glyph.closest(".react-flow__node")!.getAttribute("data-id")!, rect: glyph.getBoundingClientRect() }));
    const hits: string[] = [];
    for (const group of canvas.querySelectorAll<SVGGElement>(".react-flow__edge")) {
      const path = group.querySelector<SVGPathElement>(".react-flow__edge-path");
      // Faint context edges pass behind cards and caption plates; flow steps must not.
      if (!path || !path.getTotalLength() || Number(getComputedStyle(path).opacity) < 0.5) continue;
      const matrix = path.getScreenCTM()!, length = path.getTotalLength();
      const start = path.getPointAtLength(0).matrixTransform(matrix), end = path.getPointAtLength(length).matrixTransform(matrix);
      for (const { id, rect } of cards) {
        const isEnd = (p: DOMPoint) => p.x > rect.left - 12 && p.x < rect.right + 12 && p.y > rect.top - 12 && p.y < rect.bottom + 12;
        if (isEnd(start) || isEnd(end)) continue;
        for (let d = 0; d <= length; d += 4) {
          const p = path.getPointAtLength(d).matrixTransform(matrix);
          if (p.x > rect.left && p.x < rect.right && p.y > rect.top && p.y < rect.bottom) { hits.push(`${group.getAttribute("data-id")} through ${id}`); break; }
        }
      }
    }
    return hits;
  });
  expect(crossings).toEqual([]);
});
