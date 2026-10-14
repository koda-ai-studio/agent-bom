import { expect, test } from "@playwright/test";
import { createRequire } from "node:module";
const resolveModule = createRequire(`${__dirname}/../package.json`);
test.use({ bypassCSP: true });

const source = "agent:aws:production:planner";
const target = "agent:ingested:worker";
const snapshot = "correlated-estate";
const generation = "b".repeat(32);
const node = (id: string, label: string, data_sources: string[]) => ({ id, entity_type: "agent", label, attributes: {}, severity: "unknown", risk_score: 0, status: "active", data_sources, dimensions: {}, compliance_tags: [] });
const planner = node(source, "Cloud planner", ["aws"]);
const worker = node(target, "Ingested worker", ["ci-ingest"]);

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`shared graph preserves cross-source delegation and keyboard edge evidence ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    const incident: URL[] = [];
    const queries: Array<{root: string; scan: string}> = [];
    const legacy: string[] = [];
    await page.route("**/health", route => route.fulfill({ json: { status: "ok", demo_mode: false, deployment_mode: "fleet" } }));
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture-tenant", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (url.pathname === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: snapshot, created_at: "2026-09-23T12:00:00Z", node_count: 200, edge_count: 190, risk_summary: {}, snapshot_kind: "correlation" }] });
      if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: snapshot, agents: [worker, planner], pagination: { total: 93, limit: 24, next_cursor: "next-agents" } } });
      if (url.pathname === "/v1/graph/query") {
        const body = route.request().postDataJSON();
        queries.push({ root: body.roots[0], scan: body.scan_id });
        return route.fulfill({ json: { scan_id: snapshot, tenant_id: "fixture-tenant", created_at: "2026-10-12T00:00:00Z", roots: body.roots,
          nodes: [planner, worker], edges: [{ id: "delegation", source, target, relationship: "delegates_to", direction: "directed", weight: 1, traversable: false, evidence: { basis: "configured_delegation", source: "fixture" } }],
          attack_paths: [], interaction_risks: [], stats: { total_nodes: 2, total_edges: 1, node_counts: {}, edge_counts: {}, severity_counts: {}, risk_score: 0 },
          depth_by_node: { [source]: 0, [target]: 1 }, truncated: false, direction: "both", max_depth: 1, budget: {},
        } });
      }
      if (url.pathname === "/v1/graph/incident-edges") {
        incident.push(url);
        const selected = url.searchParams.get("node_id") === source ? planner : worker;
        return route.fulfill({ json: { scan_id: snapshot, snapshot_generation: generation, node_id: selected.id, found: true, direction: "both", limit: 24, node: selected,
          nodes: [selected.id === source ? worker : planner], edges: [{ id: "delegation", source, target, relationship: "delegates_to", direction: "directed", weight: 1, evidence: { basis: "configured_delegation" }, provenance: { source: "fixture" } }],
          next_cursor: null, completeness: { complete: true, truncated: false, sampled: false, status: "complete", total: 1, returned: 1, scope: "incident_edge_page", missing_endpoint_count: 0 } } });
      }
      if (url.pathname === "/v1/agents" || /^\/v1\/scan\//.test(url.pathname)) legacy.push(url.pathname);
      return route.fulfill({ status: 404, json: { detail: "Outside fixture scope" } });
    });

    await page.goto(`/security-graph?lens=mesh&scan=${snapshot}&agent=${encodeURIComponent(source)}`);
    await expect(page.getByRole("heading", { name: "Investigation", exact: true })).toBeVisible();
    const inspector = page.getByTestId("graph-entity-drawer");
    await expect(inspector.getByRole("heading", { name: "Cloud planner", exact: true })).toBeVisible();
    expect(queries[0]).toEqual({ root: source, scan: snapshot });
    if (width === 390) await inspector.getByRole("button", { name: "Close", exact: true }).click();
    const edge = page.locator('.react-flow__edge[data-id="delegation"]');
    await edge.focus();
    await edge.press("Enter");
    const details = page.getByLabel("Relationship details", { exact: true });
    await expect(details.getByText("Cloud planner → Ingested worker")).toBeVisible();
    await details.getByText("Technical details", { exact: true }).click();
    await expect(details.getByText("configured_delegation", { exact: true })).toBeVisible();
    await details.getByText("Recorded evidence", { exact: true }).click();
    await expect(details.locator("pre")).toBeVisible();
    await expect(details.locator("pre")).toContainText('"basis": "configured_delegation"');
    expect(legacy).toEqual([]);
    expect(errors).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.addScriptTag({ path: resolveModule.resolve("axe-core/axe.min.js") });
    const violations = await page.evaluate(async () => {
      const axe = (window as unknown as { axe: typeof import("axe-core") }).axe;
      const result = await axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } });
      return result.violations.filter(row => row.impact === "serious" || row.impact === "critical");
    });
    expect(violations).toEqual([]);
    await page.screenshot({ path: testInfo.outputPath(`delegation-${theme}-${width}.png`), fullPage: true });
    await page.keyboard.press("Escape");
    await expect(details).toHaveCount(0);
    await expect(edge).toBeFocused();
  });
}
