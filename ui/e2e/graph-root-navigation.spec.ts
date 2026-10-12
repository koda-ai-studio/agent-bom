import { expect, test } from "@playwright/test";

const first = "agent:first";
const exact = "server:with spaces/+&?";
const node = (id: string, label: string) => ({ id, label, entity_type: id.startsWith("agent:") ? "agent" : "server", attributes: {}, severity: "none", severity_id: 0, risk_score: 0, status: "active", data_sources: ["fixture"], dimensions: {}, compliance_tags: [] });
for (const theme of ["light", "dark"]) for (const width of [390, 1440]) {
  test(`canonical graph roots survive navigation ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const requested: string[] = [];
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/health", route => route.fulfill({json: {status: "ok", demo_mode: false, deployment_mode: "fleet"}}));
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (url.pathname === "/v1/jobs" || url.pathname === "/v1/graph/snapshots") return route.fulfill({ status: 503, json: { detail: "List unavailable" } });
      if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: "snapshot", agents: [node(first, "First agent")], pagination: { total: 1 } } });
      if (url.pathname === "/v1/graph/query") {
        const id = route.request().postDataJSON().roots[0]; requested.push(id);
        const found = id !== "server:missing";
        return route.fulfill({ json: { scan_id: "snapshot", tenant_id: "fixture", created_at: "2026-10-11T00:00:00Z", roots: [id],
          nodes: found ? [node(id, id === exact ? "Exact file server" : "Second server"), node(first, "First agent")] : [],
          edges: found ? [{ id: "relation", source: id, target: first, relationship: "uses", direction: "directed", weight: 1, evidence: { basis: "configured" } }] : [],
          attack_paths: [], interaction_risks: [], stats: { total_nodes: found ? 2 : 0, total_edges: found ? 1 : 0, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 },
          depth_by_node: { [id]: 0, [first]: 1 }, truncated: false, direction: "both", max_depth: 1, budget: {},
        } });
      }
      if (url.pathname === "/v1/graph/incident-edges") return route.fulfill({status: 404, json: {detail: "No supplemental evidence"}});
      return route.fulfill({ status: 404, json: { detail: "Outside fixture scope" } });
    });
    const params = new URLSearchParams({ lens: "context", scan: "snapshot", root: exact, agent: "Carried display name" });
    await page.goto(`/graph?${params}`);
    const inspector = page.getByTestId("graph-entity-drawer");
    await expect(inspector.getByRole("heading", { name: "Exact file server", exact: true })).toBeVisible();
    expect(requested).toEqual([exact]);
    await expect(page.getByRole("status").filter({ hasText: "Snapshot list unavailable" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await page.screenshot({ path: testInfo.outputPath(`exact-root-${theme}-${width}.png`), fullPage: true });
    if (width === 390) await inspector.getByRole("button", { name: "Close", exact: true }).click();
    params.set("root", "server:second");
    await page.evaluate(href => window.history.pushState(null, "", href), `/graph?${params}`);
    await expect(inspector.getByRole("heading", { name: "Second server", exact: true })).toBeVisible();
    await expect(inspector.getByRole("heading", { name: "Exact file server", exact: true })).toHaveCount(0);
    if (width === 390) await inspector.getByRole("button", { name: "Close", exact: true }).click();
    params.set("root", exact); params.set("lens", "mesh");
    await page.evaluate(href => window.history.pushState(null, "", href), `/graph?${params}`);
    await expect(page.getByRole("heading", { name: "Investigation", exact: true })).toBeVisible();
    await expect(inspector.getByRole("heading", { name: "Exact file server", exact: true })).toBeVisible();
    expect(requested).toEqual([exact, "server:second", exact]);
    if (width === 390) await inspector.getByRole("button", { name: "Close", exact: true }).click();
    params.set("root", "server:missing");
    await page.evaluate(href => window.history.pushState(null, "", href), `/graph?${params}`);
    await expect.poll(() => requested.at(-1)).toBe("server:missing");
    await expect(page.locator(".react-flow__node")).toHaveCount(0);
    expect(requested).not.toContain(first);
    expect(errors).toEqual([]);
  });
}
