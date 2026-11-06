import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect, type Page } from "@playwright/test";

type Graph = { nodes: { id: string; label: string; attributes: Record<string, unknown> }[]; edges: { id: string; source: string; target: string }[] };
const fixtures = JSON.parse(readFileSync(join(__dirname, "fixtures/k8s-projection.json"), "utf8")) as Record<"snapshot" | "tokenMounted" | "internalOnly" | "twoServices" | "clusterEstate" | "withFindings", Graph>;
const stamp = "2026-11-05T00:00:00Z";
const nodeId = (graph: Graph, label: string) => graph.nodes.find(node => node.label === label)!.id;
const CHAIN = ["ingress: prod/web", "service: prod/web", "pod: prod/web-7c9f-1", "replicaset: prod/web-7c9f", "deployment: prod/web"];
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
    if (path === "/v1/graph/rollup") return r.fulfill({ json: { ...body, mode: "rollup", top_level: [], children: [], summary: { total_nodes: graph.nodes.length }, completeness: { complete: true }, pagination: { offset: 0, limit: 100, total: 0, returned: 0, has_more: false } } });
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
}

async function open(page: Page, query = "") {
  await page.goto(`/security-graph?scan=snapshot&lens=estate&rollup=0${query}`);
  await showGraph(page);
}

/** A phone opens on its list; the graph is one tab away. */
async function showGraph(page: Page) {
  const graphTab = page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true });
  await expect(page.locator(".react-flow__node").or(graphTab).first()).toBeVisible();
  if (await graphTab.isVisible()) await graphTab.click();
  await settle(page);
}

async function settle(page: Page) {
  await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
  let previous = "", stable = 0;
  await expect.poll(async () => {
    const current = await page.locator(".react-flow__viewport").evaluate(element => getComputedStyle(element).transform);
    stable = current === previous ? stable + 1 : 0;
    previous = current;
    return stable;
  }, { intervals: [100], timeout: 10_000 }).toBeGreaterThanOrEqual(4);
}

/** What the reader actually gets: cards in frame, the smallest text they must read, pills, and edges that end away from a glyph. */
async function reading(page: Page) {
  return page.locator(".react-flow").evaluate(canvas => {
    const frame = canvas.getBoundingClientRect();
    const zoom = new DOMMatrixReadOnly(getComputedStyle(canvas.querySelector(".react-flow__viewport")!).transform).a;
    const nodes = [...canvas.querySelectorAll<HTMLElement>(".react-flow__node")];
    const boxOf = (node: Element) => (node.querySelector("[data-graph-entity]") ?? node).getBoundingClientRect();
    const framed = nodes.filter(node => { const r = boxOf(node); return r.width > 0 && r.left >= frame.left - 1 && r.right <= frame.right + 1 && r.top >= frame.top - 1 && r.bottom <= frame.bottom + 1; });
    const glyphs = new Map(nodes.flatMap(node => { const glyph = node.querySelector(".graph-entity-glyph"); return glyph ? [[node.getAttribute("data-id")!, glyph.getBoundingClientRect()] as const] : []; }));
    const detached: string[] = [];
    for (const group of canvas.querySelectorAll<SVGGElement>(".react-flow__edge")) {
      const path = group.querySelector<SVGPathElement>(".react-flow__edge-path");
      if (!path || !path.getTotalLength()) continue;
      const ctm = path.getScreenCTM()!, start = path.getPointAtLength(0).matrixTransform(ctm), end = path.getPointAtLength(path.getTotalLength()).matrixTransform(ctm);
      const near = (p: DOMPoint) => [...glyphs.values()].some(r => p.x >= r.left - 12 && p.x <= r.right + 12 && p.y >= r.top - 12 && p.y <= r.bottom + 12);
      // A virtualized map does not draw off-screen cards, so only judge ends the reader can see.
      const onScreen = (p: DOMPoint) => p.x >= frame.left && p.x <= frame.right && p.y >= frame.top && p.y <= frame.bottom;
      if ((onScreen(start) && !near(start)) || (onScreen(end) && !near(end))) detached.push(group.getAttribute("data-id") ?? "");
    }
    const text = framed.flatMap(node => [...node.querySelectorAll<HTMLElement>("[data-graph-entity] span, [data-graph-entity] p, [data-graph-entity] div")]
      .filter(element => !element.childElementCount && element.textContent?.trim() && !element.classList.contains("sr-only") && !element.closest(".sr-only"))
      .map(element => parseFloat(getComputedStyle(element).fontSize) * zoom));
    const invisible = framed.flatMap(node => [...node.querySelectorAll<HTMLElement>("[data-graph-entity] span")]
      .filter(element => element.textContent?.trim() && !element.closest(".sr-only") && getComputedStyle(element).color === getComputedStyle(canvas).backgroundColor).map(element => element.textContent));
    return { zoom, total: nodes.length, inFrame: framed.map(node => node.getAttribute("data-id")!), smallest: text.length ? Math.min(...text) : 0,
      cards: nodes.filter(node => node.querySelector(".graph-entity-glyph")).length, detached, invisible };
  });
}

const flowSelect = (page: Page) => page.getByRole("combobox", { name: "Investigation flow" });
const overflow = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

for (const theme of ["light", "dark"]) {
  test(`a real twenty-node cluster opens framed and readable at 1440 in ${theme}`, async ({ page }, info) => {
    await page.setViewportSize(VIEWPORTS[0]!);
    await serve(page, fixtures.snapshot, theme);
    await open(page);
    await expect(flowSelect(page).locator("option:checked")).toHaveText("Automatic · Exposure");
    const first = await reading(page);
    expect(first.total).toBe(20);
    expect(first.cards).toBe(20);
    expect(first.inFrame.length).toBe(20);
    expect(first.smallest).toBeGreaterThanOrEqual(11.8);
    expect(first.detached).toEqual([]);
    expect(first.invisible).toEqual([]);
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: info.outputPath(`k8s20-${theme}-1440-open.png`) });
    for (const flow of ["identity", "inventory"]) {
      await flowSelect(page).selectOption(flow);
      await settle(page);
      const view = await reading(page);
      expect(view.cards).toBe(20);
      expect(view.inFrame.length).toBeGreaterThanOrEqual(12);
      expect(view.smallest).toBeGreaterThanOrEqual(11.8);
      expect(view.detached).toEqual([]);
      await page.screenshot({ path: info.outputPath(`k8s20-${theme}-1440-${flow}.png`) });
    }
    await expect(flowSelect(page).locator('option[value="vulnerability"]')).toHaveJSProperty("disabled", true);
    await expect(flowSelect(page).locator('option[value="vulnerability"]')).toHaveText("Vulnerability (no findings)");
  });

  test(`a real twenty-node cluster stays readable at 390 in ${theme}`, async ({ page }, info) => {
    await page.setViewportSize(VIEWPORTS[1]!);
    await serve(page, fixtures.snapshot, theme);
    await open(page);
    const view = await reading(page);
    expect(view.cards).toBe(20);
    expect(view.inFrame.length).toBeGreaterThanOrEqual(1);
    expect(view.inFrame).toContain(nodeId(fixtures.snapshot, "ingress: prod/web"));
    expect(view.smallest).toBeGreaterThanOrEqual(12);
    expect(view.invisible).toEqual([]);
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: info.outputPath(`k8s20-${theme}-390-open.png`) });
    await expect(page.getByRole("group", { name: "Navigate loaded graph nodes" })).toBeVisible();
    await page.getByRole("button", { name: "Next graph node" }).click();
    await expect(page.getByRole("button", { name: "Center graph node: service: prod/web" })).toBeVisible();
    await settle(page);
    await page.screenshot({ path: info.outputPath(`k8s20-${theme}-390-next.png`) });
  });

  for (const viewport of VIEWPORTS) test(`a cluster above the former limit frames its primary path in ${theme} at ${viewport.width}`, async ({ page }, info) => {
    await page.setViewportSize(viewport);
    await serve(page, fixtures.clusterEstate, theme);
    await open(page);
    // The default opens a small preview, and Automatic says so rather than naming a flow.
    await expect(flowSelect(page).locator("option:checked")).toHaveText(viewport.width === 390 ? "Auto · preview" : "Automatic · connection preview");
    await flowSelect(page).selectOption("exposure");
    await settle(page);
    await expect(page.getByText("Return to connection preview")).toBeVisible();
    await expect(page).toHaveURL(/map_view=full/);
    await expect(page).toHaveURL(/flow=exposure/);
    const view = await reading(page);
    const path = ["ingress: prod/app-00", "service: prod/app-00"].map(label => nodeId(fixtures.clusterEstate, label));
    const phone = viewport.width < 640;
    expect(view.inFrame).toEqual(expect.arrayContaining(phone ? path.slice(0, 1) : path));
    expect(view.inFrame.length).toBeGreaterThanOrEqual(phone ? 1 : 5);
    expect(view.smallest).toBeGreaterThanOrEqual(11.8);
    if (!phone) expect(view.detached).toEqual([]);
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    await page.screenshot({ path: info.outputPath(`estate-${theme}-${viewport.width}-exposure.png`) });
    await page.reload();
    await showGraph(page);
    await expect(flowSelect(page)).toHaveValue("exposure");
    await page.getByRole("button", { name: "Reset view" }).click();
    await expect(flowSelect(page)).toHaveValue("auto");
  });

  for (const viewport of VIEWPORTS) test(`internal Services and a second route read accurately in ${theme} at ${viewport.width}`, async ({ page }, info) => {
    await page.setViewportSize(viewport);
    await serve(page, fixtures.internalOnly, theme);
    await open(page);
    await expect(flowSelect(page).locator('option[value="exposure"]')).toHaveJSProperty("disabled", true);
    await expect(flowSelect(page).locator("option:checked")).toHaveText(viewport.width === 390 ? "Auto · Identity" : "Automatic · Identity and access");
    const service = page.locator(`.react-flow__node[data-id="${nodeId(fixtures.internalOnly, "service: prod/api")}"]`);
    await expect(service).toContainText("ClusterIP (internal)", { useInnerText: false });
    await page.screenshot({ path: info.outputPath(`internal-${theme}-${viewport.width}.png`) });

    await page.unrouteAll();
    await serve(page, fixtures.twoServices, theme);
    await open(page);
    const x = (label: string) => page.locator(`.react-flow__node[data-id="${nodeId(fixtures.twoServices, label)}"]`).evaluate(node => node.getBoundingClientRect().x);
    const pod = await x("pod: prod/web-7c9f-1");
    expect(await x("ingress: prod/web")).toBeLessThan(await x("service: prod/web"));
    expect(await x("service: prod/web")).toBeLessThan(pod);
    expect(await x("service: prod/web-public")).toBeLessThan(pod);
    await page.screenshot({ path: info.outputPath(`two-services-${theme}-${viewport.width}.png`) });
  });
}

test("the exposure path runs through the controller to the identity when the token is mounted", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[0]!);
  await serve(page, fixtures.tokenMounted, "light");
  await open(page);
  const boxes = await Promise.all([...CHAIN, "service account: prod/web-sa", "Role: web-sa-reader"].map(label => page.locator(`.react-flow__node[data-id="${nodeId(fixtures.tokenMounted, label)}"]`).boundingBox()));
  const xs = boxes.map(box => box!.x);
  expect(xs).toEqual([...xs].sort((a, b) => a - b));
  expect(new Set(boxes.map(box => Math.round(box!.y))).size).toBe(1);
});

test("an unmounted token is captioned, and evidence counts exclude display objects", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[0]!);
  const assessed: Graph = { ...fixtures.snapshot, nodes: fixtures.snapshot.nodes.map(node => node.label === "ingress: prod/web" ? { ...node, attributes: { ...node.attributes, resource_id: "ing-1",
    network_reachability_assessment: { complete: true, decision: "allow", source_scope: "internet", target_id: "ing-1", evidence_refs: ["receipt-1"] } } } : node) };
  await serve(page, assessed, "light");
  await open(page);
  await expect(page.locator(`.react-flow__node[data-id="${nodeId(fixtures.snapshot, "service account: prod/web-sa")}"]`)).toContainText("token not mounted");
  await expect(page.getByLabel("Visible relationship evidence").first()).toContainText("Recorded observation");
  await expect(page.getByLabel("Visible relationship evidence").first()).not.toContainText("Mixed");
  const internet = page.locator(`.react-flow__node[data-id^="display:internet:"]`);
  await expect(internet).toHaveAttribute("aria-label", "Internet, assessed ingress to ingress: prod/web");
  await expect(page.locator(".react-flow__edge[aria-label='Assessed ingress from Internet to ingress: prod/web']")).toHaveCount(1);
  await expect(page.locator('.react-flow__edge[aria-label*="display:"]')).toHaveCount(0);

  await internet.click();
  const receipt = page.getByRole("complementary", { name: "Assessed ingress receipt" });
  await expect(receipt).toContainText("receipt-1");
  await expect(receipt).toContainText("not a connectivity test");
  await expect(receipt).toContainText("not resolved");
  await page.getByRole("button", { name: "Close assessed ingress receipt" }).click();
  await expect(receipt).toHaveCount(0);
  await page.locator(".react-flow__edge[aria-label^='Assessed ingress'] .react-flow__edge-interaction").dispatchEvent("click");
  await expect(receipt).toBeVisible();
});

test("flows pause with an explanation while the layout is being edited", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[0]!);
  await serve(page, fixtures.snapshot, "light");
  await open(page);
  await page.getByText("Layout", { exact: true }).click();
  await page.getByRole("button", { name: /unlock|edit/i }).first().click();
  await expect(flowSelect(page)).toBeDisabled();
  await expect(page.getByTestId("graph-flow-status")).toHaveText("Flows are paused while you edit the layout.");
});

test("collapse findings closes a selected finding and hides it", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[0]!);
  await serve(page, fixtures.withFindings, "light");
  await open(page);
  await flowSelect(page).selectOption("vulnerability");
  await settle(page);
  await page.getByRole("button", { name: /^Expand findings/ }).click();
  await settle(page);
  const finding = page.locator(`.react-flow__node[data-id="${nodeId(fixtures.withFindings, "CVE-2021-3711")}"]`);
  await finding.click();
  await page.getByRole("button", { name: "Collapse findings" }).click();
  await expect(finding).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Expand findings/ })).toBeVisible();
});

test("one long real label does not collapse the first view", async ({ page }) => {
  await page.setViewportSize(VIEWPORTS[0]!);
  const long: Graph = { ...fixtures.snapshot, nodes: fixtures.snapshot.nodes.map(node => node.label === "pod: prod/web-7c9f-1" ? { ...node, label: "pod: production-payments/web-frontend-7c9f4d-x2k9p-with-a-very-long-suffix-for-replicas" } : node) };
  await serve(page, long, "light");
  await open(page);
  const view = await reading(page);
  expect(view.inFrame.length).toBe(20);
});
