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
      else if (path === "/v1/traces/connectors/langfuse/pull") {
        expect(request.postDataJSON()).toMatchObject({ screen_content: false, limit: 50 });
        expect(request.headers()["x-agent-bom-csrf"]).toBe("trace-fixture");
        body = { provider: "langfuse", pulled_spans: 2, content_screened: false, content_findings: [], attack_paths: [{ trace_id: "trace-7", span_id: "span-1", tool_name: "read_file", server_name: "filesystem", vulnerability_id: "CVE-2025-1234", match_basis: "tool", severity: "high" }] };
      }
      await route.fulfill({ json: body });
    });
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/traces");
    await page.getByRole("button", { name: "Connect platforms" }).click();
    await page.getByLabel("Public key", { exact: true }).fill("fixture-public");
    await page.getByLabel("Secret key", { exact: true }).fill("fixture-secret");
    await page.getByRole("button", { name: "Pull and correlate" }).click();
    await expect(page.getByText("2 tool calls reviewed · 1 finding matches")).toBeVisible();
    await expect(page.getByLabel("Secret key", { exact: true })).toHaveValue("");
    await expect(page.getByRole("link", { name: "CVE-2025-1234" })).toHaveAttribute("href", "/findings?cve=CVE-2025-1234");
    await expect(page.getByText(/not saved to the trace explorer/)).toBeVisible();
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
      await page.screenshot({ fullPage: true, path: testInfo.outputPath(`trace-connectors-${theme}-${width}.png`) });
    }
  });
}
