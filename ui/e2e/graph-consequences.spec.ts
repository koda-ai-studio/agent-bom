import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

const scan = "assessment-fixture";
const revision = "a".repeat(32);
const node = (id: string, entity_type: string, label: string) => ({
  id, entity_type, label, status: "active", risk_score: 0, severity: "none", severity_id: 0,
  attributes: {}, compliance_tags: [], data_sources: ["fixture"], dimensions: {},
});
const nodes = [node("agent:one", "agent", "Example agent"), node("server:one", "server", "Example server")];
const edges = [{ id: "edge:one", source: "agent:one", target: "server:one", relationship: "uses", direction: "directed", weight: 1, traversable: true, evidence: {} }];

for (const theme of ["light", "dark", "mobile"]) {
  test(`consequence paths and export ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: theme === "mobile" ? 390 : 1440, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const requests: Record<string, unknown>[] = [];
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "viewer", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (path === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: scan, created_at: "2026-10-10T00:00:00Z", node_count: 2, edge_count: 1, risk_summary: {} }] });
      if (path === "/v1/inventory/summary") return route.fulfill({ json: { scan_id: scan, tenant_id: "fixture", total_assets: 2, evidence_scope: "historical_snapshot", snapshot_generation: revision } });
      if (path.startsWith("/v1/graph/node/")) return route.fulfill({ json: { scan_id: scan, snapshot_generation: revision, node: nodes[0], edges_out: edges, edges_in: [], neighbors: ["server:one"], sources: [], impact: { upstream_agents: [], affected_count: 0 } } });
      if (path === "/v1/graph/consequences") {
        requests.push(route.request().postDataJSON());
        return route.fulfill({ json: {
          schema_version: "graph.consequence.v1", tenant_id: "fixture", scan_id: scan, snapshot_generation: revision,
          assessed_at: "2026-10-11T00:00:00Z", capability: "experimental", truncated: false,
          prerequisites: { status: "not_evaluated", reason_codes: [] },
          counts: { supported: 1, conditional: 0, blocked: 1, unknown: 0, lower_bound: false },
          consequences: [
            { id: "read", status: "supported", category: "read_data", action: "storage.objects.get", resource: "projects/example/buckets/reports",
              target_node_id: "bucket:reports", node_ids: ["agent:one", "identity:reader", "bucket:reports"], node_labels: ["Research assistant", "Reports reader", "Reports bucket"], node_types: ["agent", "service_account", "data_store"],
              edge_ids: ["session-binding:one", "permission:read"], session_ids: ["session:one"], binding_ids: ["binding:reader"],
              deny_binding_ids: [], evidence_refs: ["collector:fixture"], reason_codes: [], observation: "not_recorded", observed_at: "2026-10-11T00:00:00Z" },
            { id: "delete", status: "blocked", category: "delete_resource", action: "storage.objects.delete", resource: "projects/example/buckets/reports",
              target_node_id: "bucket:reports", node_ids: ["agent:one", "identity:reader", "bucket:reports"], node_labels: ["Research assistant", "Reports reader", "Reports bucket"], node_types: ["agent", "service_account", "data_store"],
              edge_ids: ["session-binding:one"], session_ids: ["session:one"], binding_ids: [], deny_binding_ids: ["deny:delete"],
              evidence_refs: ["collector:fixture"], reason_codes: ["recorded_denial"], observation: "not_recorded", observed_at: "2026-10-11T00:00:00Z" },
          ], frontier: [{ status: "unknown", reason_codes: ["identity_session_not_recorded"], node_ids: ["agent:one", "identity:other"], edge_ids: [],
             next_collection_step: "Collect an exact identity/session binding for the alternate identity." }],
        } });
      }
      if (path === "/v1/graph" || path === "/v1/graph/query") return route.fulfill({ json: {
        scan_id: scan, nodes, edges, attack_paths: [], interaction_risks: [], roots: ["agent:one"], direction: "forward", max_depth: 1, truncated: false, depth_by_node: { "agent:one": 0, "server:one": 1 }, budget: {},
        stats: { total_nodes: 2, total_edges: 1, node_types: { agent: 1, server: 1 }, severity_counts: {}, relationship_types: { uses: 1 }, attack_path_count: 0, interaction_risk_count: 0 },
        pagination: { total: 2, offset: 0, limit: 250, has_more: false },
      } });
      return route.fulfill({ status: 503, json: { detail: "Not provided by this fixture" } });
    });
    await page.goto(`/graph?lens=lineage&scan=${scan}&node=agent:one&rollup=0`);
    const drawer = page.getByTestId("graph-entity-drawer");
    await expect(drawer).toBeVisible();
    await expect(page.locator(".react-flow__node")).toHaveCount(2);
    const panel = drawer.locator("details").filter({ has: page.locator("summary", { hasText: "Investigate consequences · experimental" }) });
    await panel.locator("summary").click();
    await expect(panel.getByRole("button", { name: "Trace consequences" })).toBeDisabled();
    expect(requests).toHaveLength(0);
    await panel.getByLabel("Assume control of this agent or principal").check();
    await panel.getByRole("button", { name: "Trace consequences" }).click();
    const workspace = page.getByRole("dialog", { name: "Consequence investigation" });
    await expect(workspace).toBeVisible();
    await expect(workspace.getByRole("heading", { name: "Read data from Reports bucket" })).toBeVisible();
    expect(requests).toEqual([expect.objectContaining({ root_node_id: "agent:one", scan_id: scan, snapshot_generation: revision, assume_control: true })]);
    await expect(workspace.getByRole("list", { name: "Selected consequence path" })).toContainText("Reports reader");
    expect(await workspace.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    await workspace.getByRole("button", { name: /Delete a resource.*Reports bucket/ }).focus();
    await page.keyboard.press("Enter");
    await expect(workspace.getByRole("heading", { name: "Delete Reports bucket" })).toBeVisible();
    await expect(workspace.getByText("Recorded denial stops this action")).toBeVisible();
    await workspace.evaluate(element => { element.scrollTop = 0; });
    await page.screenshot({ path: testInfo.outputPath(`consequences-${theme}.png`) });
    const pending = page.waitForEvent("download");
    await workspace.getByRole("button", { name: "Export consequences JSON" }).click();
    const download = await pending;
    const exported = JSON.parse(await readFile((await download.path())!, "utf8"));
    expect(exported.snapshot_generation).toBe(revision);
    expect(exported.counts.supported).toBe(1);
    expect(exported.consequences[1].status).toBe("blocked");
  });
}
