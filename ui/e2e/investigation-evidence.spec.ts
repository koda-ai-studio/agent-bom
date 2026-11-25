import { test, expect } from "@playwright/test";

const stamp = "2026-11-25T12:00:00Z";
const node = (id: string, entity_type: string, label: string) => ({ id, entity_type, label, category_uid: 0, class_uid: 0, type_uid: 0, status: "active", risk_score: 0, severity: "none", severity_id: 0, first_seen: stamp, last_seen: stamp, attributes: {}, compliance_tags: [], data_sources: ["fixture"], dimensions: {} });
const nodes = [node("agent:z", "agent", "Zebra production assistant"), node("server:z", "server", "Production tools"), node("pkg:z", "package", "Production dependency"), node("vuln:z", "vulnerability", "CVE-2026-1234"), node("agent:a", "agent", "Alphabetical unrelated assistant")];
const hops = nodes.slice(0, 4).map(n => n.id);
const edges = hops.slice(1).map((target, i) => ({ id: `e${i}`, source: hops[i], target, relationship: ["uses", "depends_on", "vulnerable_to"][i], direction: "directed", weight: 1, traversable: true, first_seen: stamp, last_seen: stamp, evidence: { source: "fixture" }, activity_id: 1 }));
const attack_paths = [{ source: hops[0], target: hops[3], hops, edges: edges.map(e => e.relationship), composite_risk: 7, summary: "Recorded production path", credential_exposure: [], tool_exposure: [], vuln_ids: ["CVE-2026-1234"] }];

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`ranked evidence stays readable on first frame in ${theme} at ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.name));
    const graph = { scan_id: "proof", tenant_id: "fixture", snapshot_generation: "generation-1", created_at: stamp, nodes, edges, attack_paths, interaction_risks: [], stats: { total_nodes: nodes.length, total_edges: edges.length, attack_paths: 1, severity_counts: {} }, pagination: { total: nodes.length, returned: nodes.length, offset: 0, limit: 100, has_more: false } };
    await page.route("**/health", r => r.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", async r => {
      const path = new URL(r.request().url()).pathname;
      if (path === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
      if (path === "/v1/inventory/summary") return r.fulfill({ json: { scan_id: "proof", tenant_id: "fixture", total_assets: nodes.length, evidence_scope: "current_estate", snapshot_generation: "generation-1" } });
      if (path === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "proof", created_at: stamp, snapshot_kind: "scan", node_count: nodes.length, edge_count: edges.length }] });
      if (path === "/v1/graph" || path === "/v1/graph/attack-paths") return r.fulfill({ json: graph });
      return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
    });
    await page.goto("/graph");
    const graphTab = page.getByRole("group", { name: "Investigation view" }).getByRole("button", { name: "Graph", exact: true });
    await expect(page.locator(".react-flow__node").or(graphTab).first()).toBeVisible();
    if (await graphTab.isVisible()) await graphTab.click();
    await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
    await expect(page.locator('.react-flow__node[data-id="agent:z"]')).toBeVisible();
    for (const id of hops) await expect(page.locator(`.react-flow__node[data-id="${id}"]`)).toBeAttached();
    expect(new URL(page.url()).searchParams.get("agent")).not.toBe("Alphabetical unrelated assistant");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(errors).toEqual([]);
    await page.screenshot({ path: info.outputPath(`ranked-${theme}-${width}.png`) });
  });
}
