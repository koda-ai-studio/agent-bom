import { expect, test } from "@playwright/test";
const root = "agent:endpoint-a:desktop";
const server = "server:endpoint-a:files";
const generation = "a".repeat(32);
const node = (id: string, kind: string, label: string) => ({ id, entity_type: kind, label, attributes: {}, severity: "none", severity_id: 0, risk_score: 0, status: "active", data_sources: ["fixture"], dimensions: {}, compliance_tags: [] });
const agent = node(root, "agent", "Desktop");
const service = node(server, "server", "File server");
const edge = { id: "recorded", source: root, target: server, relationship: "uses", direction: "bidirectional", weight: 1, evidence: { basis: "configured" } };
const session = { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] };

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`recorded relationship pages reject mixed generations ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const requests: URL[] = [];
    const queries: Array<{ scan_id: string; roots: string[] }> = [];
    let replaced = false;
    let fullReports = 0;
    await page.route("**/health", route => route.fulfill({ json: { status: "ok", demo_mode: false } }));
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: session });
      if (url.pathname === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: "snapshot", created_at: "2026-10-12T00:00:00Z", node_count: 3, edge_count: 2 }] });
      if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: "snapshot", agents: [node("agent:other", "agent", "Desktop"), agent], pagination: { total: 2 } } });
      if (url.pathname === "/v1/graph/query") {
        const body = route.request().postDataJSON(); queries.push(body);
        return route.fulfill({ json: { scan_id: body.scan_id, tenant_id: "fixture", created_at: "2026-10-12T00:00:00Z", roots: body.roots, nodes: [agent, service], edges: [edge], attack_paths: [], interaction_risks: [], stats: { total_nodes: 2, total_edges: 1, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 }, depth_by_node: { [root]: 0, [server]: 1 }, truncated: false, direction: "both", max_depth: 1, budget: {} } });
      }
      if (url.pathname === "/v1/graph/incident-edges") {
        requests.push(url);
        if (url.searchParams.has("cursor")) { replaced = true; return route.fulfill({ status: 409, json: { detail: "Snapshot replaced" } }); }
        return route.fulfill({ json: { scan_id: "snapshot", snapshot_generation: replaced ? "b".repeat(32) : generation, node_id: root, found: true, direction: "both", limit: 24, node: agent, nodes: [service], edges: [edge], next_cursor: replaced ? null : "next", completeness: { complete: replaced, truncated: !replaced, sampled: false, status: replaced ? "complete" : "partial", total: null, returned: 1, missing_endpoint_count: 0, scope: "incident_edge_page" } } });
      }
      if (/^\/v1\/scan\//.test(url.pathname)) fullReports++;
      return route.fulfill({ status: 404, json: { detail: "Outside fixture scope" } });
    });
    await page.goto(`/graph?lens=context&scan=snapshot&root=${encodeURIComponent(root)}`);
    const inspector = page.getByTestId("graph-entity-drawer");
    await expect(inspector.getByRole("heading", { name: "Desktop", exact: true })).toBeVisible();
    expect(queries[0]?.roots).toEqual([root]);
    expect(queries[0]?.scan_id).toBe("snapshot");
    await inspector.getByRole("tab", { name: "Relationships", exact: true }).click();
    await expect(inspector.getByRole("button", { name: "File server", exact: true })).toBeVisible();
    await expect(inspector.getByText("Bidirectional ↔ · Uses", { exact: true })).toBeVisible();
    await inspector.getByRole("button", { name: "Load more recorded relationships" }).click();
    await expect(inspector.getByRole("alert")).toContainText("Snapshot changed");
    await expect(inspector.getByRole("button", { name: "File server", exact: true })).toHaveCount(0);
    expect(requests[1]?.searchParams.get("snapshot_generation")).toBe(generation);
    await inspector.getByRole("button", { name: "Retry relationships" }).click();
    await expect(inspector.getByRole("button", { name: "File server", exact: true })).toBeVisible();
    expect(requests[2]?.searchParams.get("snapshot_generation")).toBeNull();
    expect(requests.every(url => url.searchParams.get("scan_id") === "snapshot")).toBe(true);
    expect(fullReports).toBe(0);
    await expect(page.getByRole("link", { name: "Inspect in lineage" })).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`recorded-pages-${theme}-${width}.png`), fullPage: true });
  });
}

for (const unavailable of [false, true]) test(`snapshot catalogue ${unavailable ? "failure" : "empty state"} does not guess a completed job identity`, async ({ page }) => {
  let graphReads = 0;
  await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", route => {
    const url = new URL(route.request().url());
    if (url.pathname === "/v1/auth/me") return route.fulfill({ json: session });
    if (url.pathname === "/v1/graph/snapshots") return route.fulfill({ json: [] });
    if (url.pathname === "/v1/inventory/summary") return unavailable
      ? route.fulfill({ status: 503, json: { detail: "Inventory unavailable" } })
      : route.fulfill({ json: { scan_id: null } });
    if (url.pathname === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: "unmapped", status: "done" }], total: 1 } });
    if (["/v1/graph/query", "/v1/graph/incident-edges"].includes(url.pathname)) graphReads++;
    return route.fulfill({ status: 404, json: { detail: "Outside fixture scope" } });
  });
  await page.goto("/graph?lens=context");
  await expect(page.getByText(unavailable ? "Could not load the unified graph" : "No graph snapshots found", { exact: true })).toBeVisible();
  expect(graphReads).toBe(0);
});
