import { test, expect, type Page } from "@playwright/test";
import { ownedFindingAggregates, routeNodeAggregates, withSemanticLayer } from "./helpers/graph-rollup-mocks";

const stamp = "2026-11-05T00:00:00Z";
const node = (id: string, entity_type: string, label: string, attributes = {}, severity = "none") => withSemanticLayer({
  id, entity_type, label, attributes, severity, status: "active", risk_score: 0, dimensions: {}, data_sources: ["synthetic-fixture"], compliance_tags: [],
});
const edge = (source: string, target: string, relationship: string, direction = "directed") => ({
  id: `${source}:${relationship}:${target}`, source, target, relationship, direction, traversable: true, weight: 1,
  evidence: { tier: "static_scan", source: "synthetic-fixture" }, first_seen: stamp, last_seen: stamp,
});
const cloud = {
  nodes: [node("account", "account", "Production", { cloud_provider: "aws" }),
    node("gateway", "api_gateway", "public-api-gateway", { internet_exposed: true }),
    node("app", "container", "checkout-api", { container_kind: "workload" }),
    node("role", "role", "checkout-runtime-role", { risk_context: { is_admin: true } }),
    node("bucket", "data_store", "customer-pii-bucket", { data_classification: "pii", risk_context: { crown_jewel: true } }),
    node("cve", "vulnerability", "CVE-2099-0001", {}, "critical"),
    node("role-finding", "misconfiguration", "Broad bucket permissions", {}, "high")],
  edges: [edge("account", "gateway", "contains"), edge("gateway", "app", "exposed_to"), edge("app", "role", "authenticates_as"),
    edge("role", "bucket", "has_permission"), edge("app", "cve", "vulnerable_to"), edge("role-finding", "role", "affects")],
};
const agent = {
  nodes: [node("agent", "agent", "Developer Copilot"), node("role", "role", "prod-ai-admin"),
    node("policy", "policy", "default-deny gateway policy"), node("host", "container", "copilot-portal:2.4.0"), node("peer", "agent", "SRE Runbook Agent")],
  edges: [edge("role", "agent", "can_access"), edge("policy", "agent", "manages"), edge("agent", "host", "hosted_on"),
    edge("agent", "peer", "shares_server", "bidirectional"), edge("peer", "host", "hosted_on")],
};

async function serve(page: Page, fixture: typeof cloud, rollup: boolean) {
  const graph = { ...fixture, scan_id: "hierarchy", tenant_id: "fixture", created_at: stamp, attack_paths: [], interaction_risks: [],
    stats: { total_nodes: fixture.nodes.length, total_edges: fixture.edges.length, severity_counts: {} } };
  const aggregate = { descendant_count: 0, issue_count: 0, by_type: {}, severity_counts: {}, worst_severity: "none", worst_severity_rank: 0,
    internet_exposed: false, exposed_count: 0, toxic_combo: false, toxic_count: 0 };
  await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (path === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: "hierarchy", created_at: stamp, node_count: fixture.nodes.length, edge_count: fixture.edges.length }] });
    if (path === "/v1/graph") return route.fulfill({ json: { ...graph, pagination: { total: fixture.nodes.length, offset: 0, limit: 100, has_more: false } } });
    if (path === "/v1/graph/rollup") return route.fulfill({ json: { ...graph, mode: "rollup",
      top_level: rollup ? fixture.nodes.map(n => ({ ...n, aggregate, is_container: false, has_children: false, direct_child_count: 0 })) : [],
      edges: rollup ? fixture.edges.map(e => ({ source: e.source, target: e.target, count: 1, relationships: [e.relationship], directions: [e.direction] })) : [],
      summary: { total_nodes: fixture.nodes.length }, completeness: { complete: true, truncated: false } } });
    return route.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
  await routeNodeAggregates(page, ownedFindingAggregates(fixture.nodes, fixture.edges));
}

async function stable(page: Page) {
  await page.waitForLoadState("networkidle");
  let last = "", settled = 0;
  await expect.poll(async () => {
    const value = await page.locator(".react-flow__viewport").evaluate(el => getComputedStyle(el).transform);
    settled = value === last ? settled + 1 : 0; last = value; return settled;
  }, { intervals: [100] }).toBeGreaterThanOrEqual(4);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`asset findings disclose without changing recorded access ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const errors: string[] = []; page.on("pageerror", error => errors.push(error.message));
    await serve(page, cloud, false);
    await page.goto("/graph?scan=hierarchy&lens=estate&rollup=0&layers=account,apiGateway,container,role,dataStore,vulnerability,misconfiguration");
    await expect(page.locator('[data-boundary-frame="account"]')).toBeVisible();
    await expect(page.locator('.react-flow__node[data-id="cve"]')).toHaveCount(0);
    const expand = page.getByRole("button", { name: "Expand 1 finding for checkout-api", exact: true });
    await expect(expand).toBeVisible();
    await expect(page.locator('.react-flow__node[data-id="bucket"]')).toBeVisible();
    await expect(page.locator('[data-compact-marker="privilege"]')).toBeVisible();
    await expect(page.locator('[data-compact-marker="sensitive"]')).toBeVisible();
    await stable(page);
    await page.screenshot({ path: info.outputPath(`cloud-first-${theme}-${width}.png`), fullPage: true });
    await expand.click();
    await expect(page.locator('.react-flow__node[data-id="cve"]')).toBeVisible();
    await expect(page.locator('.react-flow__edge[data-id="app:vulnerable_to:cve"]')).toHaveCount(1);
    await stable(page);
    await page.screenshot({ path: info.outputPath(`cloud-expanded-${theme}-${width}.png`), fullPage: true });
    await page.getByRole("button", { name: "Collapse 1 finding for checkout-api", exact: true }).click();
    await expect(page.locator('.react-flow__node[data-id="cve"]')).toHaveCount(0);
    await expect(expand).toBeVisible();
    expect(errors).toEqual([]);
  });

  test(`agent focus distinguishes access from hosting and policy ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await serve(page, agent, true);
    await page.goto("/graph?scan=hierarchy&rollup=1");
    const canvas = page.getByTestId("graph-scope-connections");
    await expect(canvas).toBeVisible();
    await page.getByLabel("Connection scope").selectOption("agent");
    await expect(canvas.locator("[data-reading-focus]")).toHaveCount(1);
    await expect(canvas.locator(".react-flow__edge")).toHaveCount(4);
    await expect(canvas.locator(".graph-relationship-label:visible")).toHaveCount(0);
    await stable(page);
    if (width === 1440) {
      const center = (id: string) => canvas.locator(`.react-flow__node[data-id="${id}"] .graph-entity-glyph`).evaluate(el => { const b = el.getBoundingClientRect(); return (b.top + b.bottom) / 2; });
      expect(Math.abs(await center("agent") - await center("role"))).toBeLessThan(1);
      expect(Math.abs(await center("agent") - await center("peer"))).toBeLessThan(1);
      expect(await center("host")).toBeLessThan(await center("agent") - 50);
      expect(await center("policy")).toBeLessThan(await center("agent") - 50);
    }
    await page.screenshot({ path: info.outputPath(`agent-${theme}-${width}.png`), fullPage: true });
  });
}
