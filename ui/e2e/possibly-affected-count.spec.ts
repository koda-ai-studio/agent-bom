import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"]) {
  for (const width of [1440, 390]) {
    test(`possible advisory count is distinct in ${theme} at ${width}px`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      const job = {
        job_id: "possible-review", status: "done", created_at: "2026-11-21T00:00:00Z",
        completed_at: "2026-11-21T00:01:00Z", request: {}, progress: [],
        result: { agents: [], blast_radius: [], summary: {
          total_agents: 1, total_mcp_servers: 0, total_packages: 1,
          total_vulnerabilities: 0, total_possibly_affected: 2, critical_findings: 0,
        } },
      };
      await page.route("**/v1/**", route => {
        const path = new URL(route.request().url()).pathname;
        if (path === "/v1/auth/me") return route.fulfill({ json: {
          authenticated: true, auth_required: false, configured_modes: [],
          recommended_ui_mode: "no_auth", tenant_id: "default", memberships: [],
        } });
        if (path.startsWith("/v1/scan/possible-review")) return route.fulfill({ json: job });
        return route.fulfill({ json: {} });
      });
      await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
      await page.goto("/scan?id=possible-review");
      const possible = page.getByText("Possibly affected · review required", { exact: true });
      await expect(possible).toBeVisible();
      await expect(possible.locator("..")).toContainText("2");
      await expect(page.getByText("Vulnerabilities", { exact: true }).locator("..")).toContainText("0");
      expect(await possible.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
      await possible.scrollIntoViewIfNeeded();
      await page.screenshot({ path: testInfo.outputPath(`possible-${theme}-${width}.png`), fullPage: true });
    });
  }
}
