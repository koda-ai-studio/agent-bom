import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"]) {
  for (const width of [1440, 390]) {
    test(`endpoint coverage keeps page and fleet denominators distinct ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      await page.route("**/v1/**", async (route) => {
        const path = new URL(route.request().url()).pathname;
        const sync = { run_id: "fixture", status: "partial", expected_count: 100, device_count: 50, gap: "permission_denied", updated_at: "2026-10-17T00:00:00Z" };
        let body: unknown = {};
        if (path === "/v1/auth/me") body = {
          authenticated: true, auth_required: true, role: "viewer", tenant_id: "fixture", memberships: [],
          role_summary: { role: "viewer", ui_role: "viewer", display_name: "Viewer", capabilities: ["inventory.read"], capability_matrix: [], can_see: [], can_do: [], cannot_do: [] },
        };
        else if (path === "/v1/endpoint-connectors") body = { connections: [{ connection: { id: "fixture", name: "Synthetic Macs", provider: "jamf", enabled: true }, sync }] };
        else if (path.endsWith("/devices")) body = {
          sync, offset: 0, limit: 25, devices: [], recent_receipts: [],
          coverage: { expected_devices: 100, observed_devices: 50, not_observed_devices: 50,
            page_devices: 0, page_stale_devices: 0, page_unknown_freshness_devices: 0, page_unbound_devices: 0,
            collection_status: "partial", collection_gap: "permission_denied" },
        };
        else if (path === "/v1/cloud/connections") body = { connections: [] };
        else if (path === "/v1/sources") body = { sources: [], count: 0 };
        else if (path === "/v1/schedules") body = [];
        else if (path === "/v1/connectors") body = { connectors: [] };
        else if (path === "/v1/discovery/providers") body = { providers: [], provider_count: 0 };
        await route.fulfill({ json: body });
      });
      await page.route("**/health", (route) => route.fulfill({ json: { status: "ok", version: "0.109.0" } }));
      await page.goto("/connections?tab=endpoints");
      await page.getByRole("button", { name: "Inspect evidence" }).click();
      const coverage = page.getByRole("region", { name: "Collection coverage" });
      await expect(coverage).toBeVisible();
      await expect(coverage).toContainText("50 observed / 100 expected devices");
      await expect(coverage).toContainText("This page: 0 devices");
      await expect(coverage).toContainText("Page counts do not describe the whole fleet");
      await expect(coverage).toContainText("permission denied");
      await expect.poll(async () => {
        const bounds = await coverage.boundingBox();
        return bounds!.x >= 0 && bounds!.x + bounds!.width <= width;
      }).toBe(true);
      await page.screenshot({ path: testInfo.outputPath(`endpoint-coverage-${theme}-${width}.png`) });
    });
  }
}
