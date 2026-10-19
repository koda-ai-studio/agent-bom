import { test, expect, type Page } from "@playwright/test";

const stamp = "2026-10-18T00:00:00Z";
const estate = "current-estate:0123456789abcdef0123456789abcdef";
const packageId = "package:pypi:langchain@0.0.150:dce85e7272e8";
const findingId = "16530e6c-ddaf-5651-ac6c-396b32d92af8";
const node = (id: string, entity_type: string, label: string, severity = "none") => ({ id, entity_type, label, severity, status: "active", risk_score: 0, attributes: {}, dimensions: {}, data_sources: ["synthetic-fixture"], compliance_tags: [] });
const nodes = [node("agent:copilot", "agent", "Member copilot"), node(packageId, "package", "langchain@0.0.150"), node(`vuln:${findingId}`, "vulnerability", "CVE-2023-36258", "critical")];
const path = { source: "agent:copilot", target: `vuln:${findingId}`, hops: nodes.map((n) => n.id), edges: ["depends_on", "has_finding"], composite_risk: 80, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: ["CVE-2023-36258"], finding_ids: [findingId] };

async function fixture(page: Page, matched: boolean, queries: URL[]) {
  await page.route("**/health", (r) => r.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", (r) => {
    const u = new URL(r.request().url());
    if (u.pathname === "/v1/auth/me") return r.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
    if (u.pathname === "/v1/graph/snapshots") return r.fulfill({ json: [{ scan_id: "showcase", created_at: stamp, snapshot_kind: "scan", node_count: 3, edge_count: 2 }] });
    if (u.pathname === "/v1/inventory/summary") return r.fulfill({ json: { schema_version: "v1", scan_id: estate, evidence_scope: "current_estate", total_assets: 3 } });
    if (u.pathname === "/v1/graph/attack-paths") {
      queries.push(u);
      const paths = matched ? [path] : [];
      return r.fulfill({ json: {
        scan_id: estate, tenant_id: "fixture", created_at: stamp, snapshot_generation: "0123456789abcdef0123456789abcdef",
        nodes: matched ? nodes : [], edges: [], attack_paths: paths, interaction_risks: [],
        stats: { total_nodes: 3, total_edges: 2, severity_counts: {}, analysis_status: { attack_path_fusion: { status: "complete", reason_codes: [], observed: {} } } },
        pagination: { total: paths.length, offset: 0, limit: 10, returned: paths.length, has_more: false, cursor: "", next_cursor: "" },
        count_metadata: { source: "persisted_graph_paths", snapshot_total: 2945, returned: paths.length, total: paths.length },
        focus: { node_id: packageId, finding_id: findingId, resolved_from: null, covers_all_matches: true },
      } });
    }
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
}

const href = `/security-graph?${new URLSearchParams({ lens: "attack-path", node: packageId, cve: "CVE-2023-36258", finding: findingId, finding_scan: "showcase" })}`;

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`finding link opens its own path on the current estate ${theme} ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript((t) => localStorage.setItem("agent-bom-theme", t), theme);
    const queries: URL[] = [];
    await fixture(page, true, queries);
    await page.goto(href);
    await expect(page.getByRole("heading", { name: "Investigation" })).toBeVisible();
    await expect(page.getByRole("heading", { name: /Member copilot → CVE-2023-36258/i })).toBeVisible();
    expect(queries[0]!.searchParams.get("scan_id")).toBe(estate);
    expect(queries[0]!.searchParams.get("node_id")).toBe(packageId);
    expect(queries[0]!.searchParams.get("finding_id")).toBe(findingId);
    await expect(page.getByText("No matching paths in loaded pages")).toHaveCount(0);
    // The title stays in view: the initial graph view must not scroll the page.
    expect(await page.evaluate(() => window.scrollY)).toBe(0);
    await expect(page.getByText(`Finding CVE-2023-36258`)).toBeVisible();
  });
}

test("a current-estate miss retries the finding's own snapshot before declaring absence", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const queries: URL[] = [];
  await fixture(page, false, queries);
  await page.goto(href);
  await expect(page.getByRole("note", { name: "Source snapshot" })).toContainText("showcase");
  await expect(page.getByText("No attack path reaches this finding in this snapshot")).toBeVisible();
  expect(queries.map((q) => q.searchParams.get("scan_id"))).toEqual(expect.arrayContaining([estate, "showcase"]));
  expect(queries[0]!.searchParams.get("advisory_id")).toBe("CVE-2023-36258");
});

test("a confirmed miss explains itself and offers the package neighbourhood, never a green complete banner", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await fixture(page, false, []);
  const noSource = new URL(href, "http://x");
  noSource.searchParams.delete("finding_scan");
  await page.goto(`${noSource.pathname}${noSource.search}`);
  await expect(page.getByText("No attack path reaches this finding in the current estate")).toBeVisible();
  await expect(page.getByText("Path analysis complete")).toHaveCount(0);
  await expect(page.getByText(/first command/i)).toHaveCount(0);
  await expect(page.getByText("agent-bom scan -p . -f graph")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Load next/ })).toHaveCount(0);
  const neighbourhood = page.getByRole("link", { name: "Open package neighbourhood" });
  await expect(neighbourhood).toHaveAttribute("href", /root=package%3Apypi%3Alangchain/);
  await expect(page.getByRole("link", { name: "Show related package and advisory paths" })).toBeVisible();
});
