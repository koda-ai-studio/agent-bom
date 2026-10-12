import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"]) {
  test(`platform trace correlation stays explicit and readable in ${theme}`, async ({ page }, testInfo) => {
    await page.addInitScript(value => { localStorage.setItem("agent-bom-theme", value); document.cookie = "agent_bom_csrf=trace-fixture; path=/"; }, theme);
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", async route => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      let body: unknown = {};
      if (path === "/v1/auth/me") body = { authenticated: true, auth_required: true, auth_method: "session", subject: "trace-operator", tenant_id: "tenant-a", role: "admin", role_summary: { role: "admin", capabilities: ["runtime.ingest", "inventory.read"] }, memberships: [] };
      else if (path === "/v1/posture/counts") body = { has_traces: true, has_gateway: true, scan_count: 1, deployment_mode: "local" };
      else if (path === "/v1/runtime/trace-explorer") body = { sessions: [], span_count: 0, session_count: 0, blocked_count: 0 };
      else if (path === "/v1/cloud/connections") body = { connections: [] };
      else if (path === "/v1/sources") body = { sources: [] };
      else if (path === "/v1/schedules") body = [];
      else if (path === "/v1/connectors") body = { connectors: [] };
      else if (path === "/v1/discovery/providers") body = { providers: [] };
      else if (path === "/v1/traces/connectors") body = { connections: [{ id: "production", provider: "langfuse", display_name: "Production traces" }], connectors: [] };
      else if (path === "/v1/traces/connectors/langfuse/collection") body = { status: "partial", persisted: 100, pages: 1, retry_after_seconds: 0 };
      else if (path === "/v1/traces/connectors/langfuse/collect") {
        expect(request.postDataJSON()).toEqual({ connection_id: "production" });
        body = { status: "failed", persisted: 100, pages: 1, retry_after_seconds: 900, last_error: "rate_limited" };
      }
      else if (path === "/v1/traces/connectors/langfuse/pull") {
        expect(request.postDataJSON()).toMatchObject({ connection_id: "production", screen_content: false, limit: 50, max_pages: 3 });
        expect(request.postDataJSON()).not.toHaveProperty("credentials");
        expect(request.headers()["x-agent-bom-csrf"]).toBe("trace-fixture");
        body = { provider: "langfuse", pulled_spans: 2, content_screened: false, content_findings: [], attack_paths: [{ trace_id: "trace-7", span_id: "span-1", tool_name: "read_file", server_name: "filesystem", vulnerability_id: "CVE-2025-1234", match_basis: "tool", severity: "high" }], import: { import_id: "trace-import-1", revision: 2, complete: true, status: "complete", coverage: "window_traversed", window_start: "2026-10-11T00:00:00Z", window_end: "2026-10-12T00:00:00Z", counts_scope: "this_request", counts: { fetched: 2, imported: 2, unchanged: 0, rejected: 0, committed_pages: 1, failed_pages: 0 }, rejected_reasons: {}, total_rejected: 0, error: null, content_retained: false } };
      }
      await route.fulfill({ json: body });
    });
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/traces");
    await page.getByRole("link", { name: "Connect platforms" }).click();
    await expect(page).toHaveURL(/connections\?tab=traces/);
    await page.getByLabel("Managed connection").selectOption("production");
    await expect(page.getByLabel("Secret key", { exact: true })).toHaveCount(0);
    await expect(page.getByText("100 observations saved · 1 pages committed")).toBeVisible();
    await page.getByRole("button", { name: "Collect next page" }).click();
    await expect(page.getByText(/Provider rate limit/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Collect next page" })).toBeDisabled();
    await page.getByRole("button", { name: "Pull and correlate" }).click();
    await expect(page.getByText("2 native observations collected · 1 finding matches")).toBeVisible();
    await expect(page.getByLabel("Secret key", { exact: true })).toHaveCount(0);

    await expect(page.getByRole("link", { name: "CVE-2025-1234" })).toHaveAttribute("href", "/findings?cve=CVE-2025-1234");
    await expect(page.getByText(/2 new observations retained/)).toBeVisible();
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
      await page.screenshot({ fullPage: true, path: testInfo.outputPath(`trace-connectors-${theme}-${width}.png`) });
    }
  });
}
