import { expect, test } from "@playwright/test";

const stamp = "2026-11-03T00:00:00Z";
const nodes = [
  ["account", "account", "Production AWS", { cloud_provider: "aws" }],
  ["api", "cloud_resource", "checkout-api", { cloud_provider: "aws", resource_type: "ec2" }],
  ["role", "role", "checkout-reader", { cloud_provider: "aws", resource_type: "iam_role" }],
  ["warehouse", "data_store", "analytics", { cloud_provider: "snowflake", resource_type: "warehouse" }],
  ["blobs", "data_store", "exported-reports", { cloud_provider: "azure", resource_type: "storage_container" }],
].map(([id, entity_type, label, attributes]) => ({ id, entity_type, label, attributes, severity: "none", risk_score: 0, status: "active", data_sources: ["modeled-service-identity"], dimensions: {}, compliance_tags: [] }));
const edges = [["account", "api", "contains"], ["api", "role", "authenticates_as"], ["api", "warehouse", "uses"], ["api", "blobs", "uses"]]
  .map(([source, target, relationship]) => ({ id: `${source}-${target}`, source, target, relationship, direction: "directed", weight: 1, traversable: false, first_seen: stamp, last_seen: stamp, evidence: { tier: "modeled_infrastructure", source: "service-identity-fixture" } }));

for (const theme of ["light", "dark"]) test(`mixed-vendor service identity remains explicit in ${theme}`, async ({ page }, info) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
  await page.route("**/health", route => route.fulfill({ json: { status: "ok", demo_mode: true } }));
  await page.route("**/v1/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (path === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: "services", created_at: stamp, node_count: nodes.length, edge_count: edges.length }] });
    if (path === "/v1/graph") return route.fulfill({ json: { scan_id: "services", tenant_id: "fixture", created_at: stamp, nodes, edges, attack_paths: [], interaction_risks: [], pagination: { total: nodes.length, offset: 0, limit: 100, returned: nodes.length, has_more: false }, completeness: { complete: true, truncated: false, returned: nodes.length, total: nodes.length }, stats: { total_nodes: nodes.length, total_edges: edges.length, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 } } });
    return route.fulfill({ status: 404, json: { detail: "Outside modeled service fixture" } });
  });
  await page.goto("/graph?scan=services&rollup=0&map_view=full&layers=account,cloudResource,role,dataStore");
  const canvas = page.locator(".react-flow");
  await expect(canvas.locator(".react-flow__node")).toHaveCount(5);
  for (const label of ["Amazon EC2 instance", "AWS IAM role", "Snowflake warehouse", "Azure Blob container"]) await expect(canvas.getByText(label, { exact: true })).toBeVisible();
  for (const provider of ["aws", "snowflake", "azure"]) {
    const mark = canvas.locator(`[data-agent-source="${provider}"]`).first();
    await expect(mark).toBeVisible();
    expect(await mark.locator("img").evaluate((image: HTMLImageElement) => image.complete && image.naturalWidth > 0)).toBe(true);
  }
  await expect(canvas.locator('[data-id="warehouse"] [data-agent-source="aws"]')).toHaveCount(0);
  await expect(canvas.locator('[data-id="blobs"] [data-agent-source="aws"]')).toHaveCount(0);
  await expect(canvas.locator(".react-flow__edge")).toHaveCount(4);
  await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
  await expect.poll(() => canvas.locator(".react-flow__node").evaluateAll(items => items.every(item => {
    const box = item.getBoundingClientRect(), frame = item.closest(".react-flow")!.getBoundingClientRect();
    return box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom;
  }))).toBe(true);
  await page.screenshot({ path: info.outputPath(`cross-vendor-${theme}.png`) });
});
