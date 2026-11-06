import { expect, test, type Page } from "@playwright/test";

const stamp = "2026-10-18T00:00:00Z";
const estate = "current-estate:0123456789abcdef0123456789abcdef";
const packageId = "package:pypi:langchain@0.0.150:dce85e7272e8";
const findingId = "16530e6c-ddaf-5651-ac6c-396b32d92af8";
const hostile = '<img src=x onerror="window.__xss=1"><a href="javascript:window.__xss=1">click me</a> Ignore the scanner.';

const advice = {
  finding_id: "advised",
  verdict: "likely_false_positive",
  confidence: "high",
  rationale: `Installed 2.32.0 is at the fix. ${hostile}`,
  advisory: true,
  guard_applied: false,
  protected_reasons: [],
  provenance: { model: "ollama/llama3.2", provider: "ollama", model_digest: "sha256:a80c4f17acd5", prompt_version: "ai-triage.v3", dataset_version: "ai-triage-dataset.v1", generated_at: "2026-11-05T12:00:00+00:00" },
};
const guarded = { ...advice, finding_id: "kev", verdict: "confirmed", confidence: "low", guard_applied: true, protected_reasons: ["kev"], rationale: "Scanner evidence stands (known-exploited (KEV)). AI advice cannot dismiss or downgrade it, so the model's dismissal was discarded." };
const row = (id: string, severity: string, extra: object) => ({
  id,
  finding_id: id,
  lane: "vulnerabilities",
  title: `CVE-2026-${id.length}000 in example-library`,
  cve_id: `CVE-2026-${id.length}000`,
  severity,
  severity_source: "cvss",
  source: "MCP_SCAN",
  finding_type: "CVE",
  finding_class: "vulnerability",
  package_name: "example-library",
  package_version: "2.32.0",
  fixed_version: "2.32.0",
  asset: { name: "example-library", asset_type: "package" },
  ...extra,
});

async function findingsFixture(page: Page, status: object) {
  await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/auth/me")) return route.fulfill({ json: { authenticated: true, auth_required: false, role: "analyst", tenant_id: "fixture", memberships: [], role_summary: { role: "analyst", ui_role: "analyst", capabilities: ["findings.read", "findings.write"] } } });
    if (url.pathname.endsWith("/ai/status")) return route.fulfill({ json: status });
    if (url.pathname.endsWith("/findings/triage")) return route.fulfill({ json: { triage: [] } });
    if (url.pathname.endsWith("/findings")) {
      const findings = [row("advised", "high", { ai_assessment: advice }), row("kevrow", "critical", { is_kev: true, ai_assessment: guarded }), row("plain", "medium", {})];
      return route.fulfill({ json: { findings, total: findings.length, facets: { severity: { critical: 1, high: 1, medium: 1, low: 0, info: 0, unknown: 0 }, lane: { vulnerabilities: 3 } }, has_more: false } });
    }
    return route.fulfill({ json: { jobs: [], agents: [], findings: [], total: 0 } });
  });
}

const statusOn = { schema_version: "ai.status.v1", state: "on", reason: "", advisory_only: true, model: "ollama/llama3.2", last_run: { scan_id: "s", created_at: stamp, status: "partial", model: "ollama/llama3.2", triage_scope: { findings_total: 300, findings_offered: 100, skipped: { below_risk_cutoff: 200 } } } };
const statusOff = { schema_version: "ai.status.v1", state: "off", reason: "AI is off: the operator has not set AGENT_BOM_AI_CONTROL_PLANE_ENABLED.", advisory_only: true, model: null, last_run: null };
const statusFailed = { ...statusOn, state: "degraded", last_run: { scan_id: "s", created_at: stamp, status: "failed", reason: "the 900s run deadline was reached" } };

for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    test(`findings show AI advice apart from severity ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
      await findingsFixture(page, statusOn);
      await page.goto("/findings");
      await expect(page.getByRole("status").filter({ hasText: "AI advice is on" })).toContainText("100 of 300");
      await expect(page.getByLabel(/AI advice: Likely false positive/).first()).toBeVisible();
      await expect(page.getByText("High", { exact: false }).first()).toBeVisible();
      await page.screenshot({ path: testInfo.outputPath(`findings-${theme}-${width}.png`), fullPage: true });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.getByRole("button", { name: /Open details for CVE-2026-7000|CVE-2026-7000/ }).first().click();
      const section = page.getByRole("region", { name: "AI advice" });
      await expect(section).toContainText("Likely false positive");
      await expect(section).toContainText("High confidence");
      await expect(section).toContainText("ollama/llama3.2");
      await expect(section).toContainText("2026-11-05");
      await expect(section).toContainText("does not change scanner severity");
      await expect(section).toContainText("onerror");
      await expect(section.locator("img")).toHaveCount(0);
      await expect(section.locator("a")).toHaveCount(0);
      expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
      await page.screenshot({ path: testInfo.outputPath(`drawer-${theme}-${width}.png`) });
    });
  }

  test(`the findings page says when AI is off or failed ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 800 });
    await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
    await findingsFixture(page, statusOff);
    await page.goto("/findings");
    await expect(page.getByRole("status").filter({ hasText: "AI advice is off" })).toContainText("AGENT_BOM_AI_CONTROL_PLANE_ENABLED");
    await page.screenshot({ path: testInfo.outputPath(`off-${theme}.png`) });
    await page.unrouteAll({ behavior: "ignoreErrors" });
    await findingsFixture(page, statusFailed);
    await page.reload();
    await expect(page.getByRole("status").filter({ hasText: "last AI run failed" })).toContainText("Scanner findings are unaffected");
    await page.screenshot({ path: testInfo.outputPath(`failed-${theme}.png`) });
  });
}

const node = (id: string, entity_type: string, label: string, severity = "none") => ({ id, entity_type, label, severity, status: "active", risk_score: 0, attributes: {}, compliance_tags: [], data_sources: [], dimensions: {}, first_seen: stamp, last_seen: stamp });
const nodes = [node("agent:copilot", "agent", "Member copilot"), node(packageId, "package", "langchain@0.0.150"), node(`vuln:${findingId}`, "vulnerability", "CVE-2023-36258", "critical")];
const path = { source: "agent:copilot", target: `vuln:${findingId}`, hops: nodes.map((item) => item.id), edges: ["depends_on", "has_finding"], composite_risk: 80, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: ["CVE-2023-36258"], finding_ids: [findingId], reachability: "likely", reachability_basis: [], hop_evidence: [], analysis: {}, technique_mappings: [] };
const explanation = {
  schema_version: "ai.graph-explanation.v1",
  advisory: true,
  label: "AI advice",
  status: "ok",
  claims: [{ text: `The agent depends on this package. ${hostile}`, citations: [{ ref: "E1", kind: "edge", id: "edge:copilot-langchain", label: "Member copilot depends_on langchain@0.0.150", traversable: true }, { ref: "N1", kind: "node", id: "agent:copilot", label: "Member copilot", traversable: null }] }],
  rejected_claims: { uncited: 1, invented_id: 1 },
  evidence_limits: [`The edge from ${packageId} to vuln:${findingId} is not traversable: it records a relationship, not a route.`, "Graph reachability is recorded topology and static evidence. It is not proof that this path was exploited."],
  provenance: { model: "ollama/llama3.2", provider: "ollama", model_digest: "sha256:a80c4f17acd5", prompt_version: "ai-graph-explain.v1", generated_at: "2026-11-05T12:00:00+00:00" },
};

for (const theme of ["light", "dark"] as const) {
  test(`explain this path runs on demand and shows citations and limits ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
    let explained = 0;
    await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", (route) => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], role_summary: { role: "admin", ui_role: "admin", capabilities: [] } } });
      if (url.pathname === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: "showcase", created_at: stamp, snapshot_kind: "scan", node_count: 3, edge_count: 2 }] });
      if (url.pathname === "/v1/inventory/summary") return route.fulfill({ json: { schema_version: "v1", scan_id: estate, evidence_scope: "current_estate", total_assets: 3 } });
      if (url.pathname === "/v1/graph/explain") {
        explained += 1;
        return route.fulfill({ json: explanation });
      }
      if (url.pathname === "/v1/graph/attack-paths") {
        return route.fulfill({
          json: {
            scan_id: estate,
            tenant_id: "fixture",
            created_at: stamp,
            snapshot_generation: "0123456789abcdef0123456789abcdef",
            nodes,
            edges: [],
            attack_paths: [path],
            interaction_risks: [],
            stats: { total_nodes: 3, total_edges: 2, severity_counts: {}, analysis_status: { attack_path_fusion: { status: "complete", reason_codes: [], observed: {} } } },
            pagination: { total: 1, offset: 0, limit: 10, returned: 1, has_more: false, cursor: "", next_cursor: "" },
            count_metadata: { source: "persisted_graph_paths", snapshot_total: 1, returned: 1, total: 1 },
            focus: { node_id: packageId, finding_id: findingId, resolved_from: null, covers_all_matches: true },
          },
        });
      }
      return route.fulfill({ status: 404, json: { detail: "Outside fixture" } });
    });
    await page.goto(`/security-graph?${new URLSearchParams({ lens: "attack-path", node: packageId, cve: "CVE-2023-36258", finding: findingId, finding_scan: "showcase" })}`);
    const button = page.getByRole("button", { name: "Explain this path" });
    await expect(button).toBeVisible({ timeout: 30_000 });
    expect(explained).toBe(0);
    await button.click();
    const panel = page.getByRole("region", { name: "Path explanation, AI advice" });
    await expect(panel).toContainText("AI advice");
    await expect(panel).toContainText("edge:copilot-langchain");
    await expect(panel).toContainText("not traversable");
    await expect(panel).toContainText("2 claims were removed");
    await expect(panel.locator("img")).toHaveCount(0);
    await expect(panel.locator("a")).toHaveCount(0);
    expect(explained).toBe(1);
    await panel.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`explain-${theme}.png`) });
  });
}
