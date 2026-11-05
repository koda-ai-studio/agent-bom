import { test, expect, type Page } from "@playwright/test";

const stamp = "2026-11-05T00:00:00Z";
const node = (id: string, entity_type: string, attributes = {}) => ({ id, entity_type, label: id, attributes, status: "active", severity: "none", risk_score: 0, dimensions: {}, data_sources: ["synthetic-fixture"], compliance_tags: [] });
const nodes = [node("account", "account"), node("cluster", "cluster"), node("deployment", "container", { kubernetes_kind: "Deployment", container_kind: "workload" }),
  node("pod", "container", { kubernetes_kind: "Pod", container_kind: "pod" }), node("endpoint", "api_gateway", { resource_id: "api-1", network_reachability_assessment: { complete: true, source_scope: "internet", decision: "allow", target_id: "api-1", evidence_refs: ["fixture-receipt"] } }),
  node("role", "role"), node("bucket", "data_store"), { ...node("CVE-2099-0001", "vulnerability"), severity: "high" }];
const edge = (source: string, target: string, relationship: string) => ({ id: `${source}:${relationship}:${target}`, source, target, relationship, traversable: false, direction: "directed", weight: 1, evidence: { tier: "static_scan", source: "synthetic-fixture" }, first_seen: stamp, last_seen: stamp });
const edges = [edge("account", "cluster", "contains"), edge("cluster", "deployment", "contains"), edge("deployment", "pod", "contains"), edge("endpoint", "pod", "exposed_to"), edge("pod", "role", "assumes"), edge("role", "bucket", "has_permission"), edge("pod", "CVE-2099-0001", "vulnerable_to")];

async function settle(page: Page) {
  let previous = "", stable = 0;
  await expect.poll(async () => {
    const transform = await page.locator(".react-flow__viewport").evaluate(e => getComputedStyle(e).transform);
    stable = transform === previous ? stable + 1 : 0; previous = transform;
    return stable;
  }, { intervals: [100] }).toBeGreaterThanOrEqual(4);
}

async function expectFramed(page: Page) {
  await expect.poll(() => page.locator(".react-flow").evaluate(canvas => {
    const frame = canvas.getBoundingClientRect();
    return [...canvas.querySelectorAll(".react-flow__node")].filter(n => {
      const r = n.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && (r.left < frame.left - 1 || r.right > frame.right + 1 || r.top < frame.top - 1 || r.bottom > frame.bottom + 1);
    }).map(n => n.getAttribute("data-id"));
  })).toEqual([]);
}

for (const theme of ["light", "dark"]) test(`distinct flows, finding drilldown and deployment context in ${theme}`, async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1600, height: 1000 });
  await page.addInitScript(theme => localStorage.setItem("agent-bom-theme", theme), theme);
  await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
  const graph = { scan_id: "snapshot", tenant_id: "fixture", created_at: stamp, nodes, edges, attack_paths: [], interaction_risks: [], stats: { total_nodes: nodes.length, total_edges: edges.length, severity_counts: {} } };
  await page.route("**/v1/**", r => {
    const path = new URL(r.request().url()).pathname;
    if (path === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (path === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "snapshot", created_at: stamp, snapshot_kind: "scan", node_count: nodes.length, edge_count: edges.length }] });
    if (path === "/v1/graph/query") return r.fulfill({ json: { ...graph, roots: [], depth_by_node: {}, truncated: false, direction: "both", max_depth: 3, budget: {} } });
    if (path === "/v1/graph") return r.fulfill({ json: { ...graph, pagination: { total: nodes.length, offset: 0, limit: 100, returned: nodes.length, has_more: false } } });
    if (path.startsWith("/v1/graph/node/")) {
      const id = decodeURIComponent(path.split("/").at(-1)!);
      return r.fulfill({ json: { node: nodes.find(n => n.id === id), sources: [], edges_in: edges.filter(e => e.target === id), edges_out: edges.filter(e => e.source === id), neighbors: [], impact: { node_id: id, affected_nodes: [], affected_by_type: {}, affected_count: 0, max_depth_reached: 0 }, completeness: { complete: true } } });
    }
    if (path === "/v1/graph/rollup") return r.fulfill({ json: { ...graph, mode: "rollup", top_level: [], children: [], summary: { total_nodes: nodes.length }, completeness: { complete: true }, pagination: { offset: 0, limit: 100, total: 0, returned: 0, has_more: false } } });
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
  await page.goto("/security-graph?scan=snapshot&lens=estate&rollup=0&layers=account,cluster,apiGateway,container,role,dataStore,vulnerability");
  const flow = page.getByRole("combobox", { name: "Investigation flow" });
  await expect(flow).toBeVisible();
  await flow.selectOption("exposure");
  await expect(page.locator('.react-flow__node[data-id="display:internet:endpoint"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="deployment"]')).toBeVisible();
  await expect(page.locator('[data-graph-entity="finding-group"]')).toBeVisible();
  await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
  await settle(page);
  await expectFramed(page);
  await page.screenshot({ path: testInfo.outputPath(`exposure-${theme}.png`), fullPage: false });
  await page.getByRole("button", { name: "Expand 1 finding for pod", exact: true }).last().click();
  const finding = page.locator('.react-flow__node[data-id="CVE-2099-0001"]');
  await expect(finding).toBeVisible();
  await finding.click();
  await expect(page.getByText("CVE-2099-0001", { exact: true }).last()).toBeVisible();
  await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
  await settle(page);
  await page.screenshot({ path: testInfo.outputPath(`finding-${theme}.png`), fullPage: false });
  for (const scenario of ["identity", "vulnerability", "inventory"]) {
    await flow.selectOption(scenario);
    await expect(page.locator('.react-flow__node[data-id="display:internet:endpoint"]')).toHaveCount(0);
    await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
    const entry = scenario === "identity" ? "role" : scenario === "vulnerability" ? "pod" : "account";
    await expect(async () => {
      const frame = await page.locator(".react-flow").boundingBox();
      const box = await page.locator(`.react-flow__node[data-id="${entry}"]`).boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(frame!.x);
      expect(box!.x + box!.width).toBeLessThanOrEqual(frame!.x + frame!.width + 1);
      expect(box!.y).toBeGreaterThanOrEqual(frame!.y);
      expect(box!.y + box!.height).toBeLessThanOrEqual(frame!.y + frame!.height + 1);
    }).toPass();
    await settle(page);
    await expectFramed(page);
    await page.screenshot({ path: testInfo.outputPath(`${scenario}-${theme}.png`), fullPage: false });
  }
  await page.setViewportSize({ width: 390, height: 844 });
  const graphTab = page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true });
  await expect(graphTab).toBeVisible();
  await graphTab.click();
  await flow.selectOption("exposure");
  await expect(page.getByRole("group", { name: "Navigate loaded graph nodes" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Next graph node" })).toBeEnabled();
  await settle(page);
  await page.screenshot({ path: testInfo.outputPath(`mobile-${theme}.png`), fullPage: false });
});
