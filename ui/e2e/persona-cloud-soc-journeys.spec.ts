import { expect, test, type Page } from "@playwright/test";

// Cloud and SOC persona journeys over a recorded fixture: a Snowflake → AWS
// storage chain reached from the path queue, and a new path opened from the
// changes panel with every hop shown.
const scanId = "scan-persona-fixture";
const createdAt = "2026-10-20T00:00:00Z";

function node(id: string, entityType: string, label: string, attributes: Record<string, unknown> = {}) {
  return {
    id, entity_type: entityType, label, category_uid: 0, class_uid: 0, type_uid: 0, status: "active", risk_score: 0,
    severity: "none", severity_id: 0, first_seen: createdAt, last_seen: createdAt, attributes, compliance_tags: [],
    data_sources: ["scan"], dimensions: { cloud_provider: String(attributes.cloud_provider ?? "") },
  };
}

function edge(source: string, target: string, relationship: string) {
  return {
    id: `${source}->${target}:${relationship}`, source, target, relationship, direction: "directed", weight: 1, traversable: true,
    first_seen: createdAt, last_seen: createdAt, evidence: {}, activity_id: 1,
  };
}

const sf = (kind: string, name: string, resourceType = kind) =>
  node(`snowflake:${kind}:NS_00:${name}`, kind === "table" || kind === "stage" ? "data_store" : "cloud_resource", name,
    { cloud_provider: "snowflake", account_id: "NS_00", resource_type: resourceType });
const table = sf("table", "risk-scores");
const stage = sf("stage", "audit-evidence");
const integration = sf("storage_integration", "audit-evidence-s3-integration");
const bucket = node("aws:bucket:1000:audit-evidence-archive", "data_store", "audit-evidence-archive", { cloud_provider: "aws", account_id: "1000", resource_type: "bucket" });
const agent = node("agent:claims", "agent", "Claims Agent");
const server = node("server:etl", "server", "etl-server", { cloud_provider: "mcp" });
const bob = node("user:bob", "user", "bob@contractor (external)", { cloud_provider: "aws" });
const bastion = node("cloud:bastion", "cloud_resource", "prod-bastion (EC2)", { cloud_provider: "aws", resource_type: "ec2" });

const crossVendorPath = {
  source: table.id, target: bucket.id, hops: [table.id, stage.id, integration.id, bucket.id],
  edges: ["depends_on", "depends_on", "can_access"], composite_risk: 52,
  summary: "risk-scores depends on audit-evidence-s3-integration, which can access the bucket.",
  credential_exposure: [], tool_exposure: [], vuln_ids: [], finding_ids: [], reachability: "likely", reachability_basis: ["recorded_identifier_match"],
};
const agentPath = { ...crossVendorPath, source: agent.id, target: server.id, hops: [agent.id, server.id], edges: ["uses"], composite_risk: 90, summary: "Agent uses server." };
const bobPath = { ...crossVendorPath, source: bob.id, target: bastion.id, hops: [bob.id, bastion.id], edges: ["has_permission"], composite_risk: 100, summary: "bob reaches prod-bastion." };

function page_(paths: typeof crossVendorPath[], nodes: ReturnType<typeof node>[], extra: Record<string, unknown> = {}) {
  const edges = paths.flatMap(path => path.hops.slice(1).map((hop, index) => edge(path.hops[index]!, hop, path.edges[index]!)));
  return {
    scan_id: scanId, tenant_id: "default", created_at: createdAt, nodes, edges, attack_paths: paths, interaction_risks: [],
    stats: { total_nodes: 8, total_edges: 6, node_types: {}, severity_counts: {}, relationship_types: {}, attack_path_count: 3, interaction_risk_count: 0, max_attack_path_risk: 100, highest_interaction_risk: 0 },
    pagination: { total: paths.length, offset: 0, limit: 25, cursor: "", next_cursor: "", has_more: false },
    count_metadata: { source: "derived_graph_paths", returned: paths.length, total: paths.length, snapshot_total: 3, materialized_paths: 0, derived_paths: 3 },
    snapshot_generation: "g".repeat(32), ...extra,
  };
}

const facets = {
  unit: "paths", snapshot_paths: 3, cross_vendor_paths: 1, covers_all_paths: true, selected: null,
  pairs: [{ source_vendor: "snowflake", target_vendor: "aws", paths: 1 }],
};

async function routeApi(page: Page) {
  await page.route("**/v1/**", route => route.fulfill({ status: 404, json: { detail: "Outside persona fixture" } }));
  await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/auth/me", route => route.fulfill({ json: {
    authenticated: true, auth_required: false, configured_modes: [], recommended_ui_mode: "no_auth", auth_method: null, subject: null,
    role: null, role_summary: null, tenant_id: "default", memberships: [], request_id: "r", trace_id: "t", span_id: "s",
  } }));
  await page.route("**/v1/posture/counts", route => route.fulfill({ json: { critical: 0, high: 0, medium: 0, low: 0, total: 0, kev: 0, compound_issues: 0 } }));
  await page.route("**/v1/inventory/summary**", route => route.fulfill({ json: {
    scan_id: scanId, tenant_id: "default", total_assets: 8, evidence_scope: "historical_snapshot", snapshot_generation: "a".repeat(32),
  } }));
  await page.route("**/v1/graph/snapshots**", route => route.fulfill({ json: [{ scan_id: scanId, created_at: createdAt, node_count: 8, edge_count: 6, risk_summary: {} }] }));
  await page.route("**/v1/graph/attack-paths?**", route => {
    const url = new URL(route.request().url());
    const focused = url.searchParams.get("node_id");
    if (focused === bob.id) return route.fulfill({ json: page_([bobPath], [bob, bastion], { focus: { node_id: bob.id, finding_id: null, resolved_from: null, covers_all_matches: true } }) });
    return route.fulfill({ json: page_([bobPath, agentPath, crossVendorPath], [bob, bastion, agent, server, table, stage, integration, bucket]) });
  });
  await page.route("**/v1/graph/attack-paths/cross-vendor?**", route => {
    const url = new URL(route.request().url());
    const narrowed = url.searchParams.get("source_vendor") || url.searchParams.get("target_vendor");
    return route.fulfill({ json: page_([crossVendorPath], [table, stage, integration, bucket], { vendor_facets: { ...facets, selected: narrowed ? { source_vendor: url.searchParams.get("source_vendor") } : null } }) });
  });
}

async function openQueue(page: Page) {
  if ((page.viewportSize()?.width ?? 1440) < 1024) await page.getByRole("button", { name: /^Paths & filters/ }).click();
  else await page.locator("#investigation-queue > summary").click();
}

test("cloud persona reaches a Snowflake → AWS path from the queue in three clicks", async ({ page }) => {
  await routeApi(page);
  await page.goto("/security-graph");
  const detail = page.getByRole("region", { name: "Selected path detail" });
  await expect(detail).toContainText("bob@contractor");
  await openQueue(page); // 1
  await page.getByRole("button", { name: "From Snowflake · 1 path" }).click(); // 2
  await page.getByRole("button", { name: "To AWS · 1 path" }).click(); // 3
  await expect(page).toHaveURL(/cross_vendor=snowflake%3Eaws/);
  await expect(page.getByText("Cross-vendor · Snowflake → AWS").first()).toBeVisible();
  if ((page.viewportSize()?.width ?? 1440) < 1024) await page.getByRole("button", { name: "Selected path" }).click();
  for (const hop of ["risk-scores", "audit-evidence", "audit-evidence-s3-integration", "audit-evidence-archive"]) {
    await expect(detail.getByText(hop, { exact: true }).first()).toBeVisible();
  }
  await expect(detail.getByText("Stage", { exact: true }).first()).toBeVisible();
});

test("SOC investigate opens the exact new path with every hop", async ({ page }) => {
  await routeApi(page);
  const selected = `${bob.id}::${bastion.id}::${bob.id}->${bastion.id}`;
  await page.goto(`/security-graph?${new URLSearchParams({ scan: scanId, node: bob.id, selected_path: selected, path_view: "path" })}`);
  const detail = page.getByRole("region", { name: "Selected path detail" });
  await expect(detail).toContainText("bob@contractor (external) → prod-bastion (EC2)");
  await expect(detail.getByText("bob@contractor (external)", { exact: true }).first()).toBeVisible();
  await expect(detail.getByText("prod-bastion (EC2)", { exact: true }).first()).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`selected_path=${encodeURIComponent(selected).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
});
