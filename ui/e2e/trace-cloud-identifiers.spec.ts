import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";

const axeSource = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

for (const theme of ["light", "dark"]) for (const width of [1280, 390]) {
  test(`native cloud identifiers retain uncertainty ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, auth_method: "anonymous", tenant_id: "fixture", role: "admin", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" } });
      if (path === "/v1/posture/counts") return route.fulfill({ json: { has_traces: true, has_gateway: true, scan_count: 1 } });
      if (path === "/v1/runtime/trace-explorer") return route.fulfill({ json: {
        schema_version: "1", tenant_id: "fixture", span_count: 1, session_count: 1, blocked_count: 0,
        sessions: [{ session_id: "trace", blocked_count: 0, observed_count: 1, spans: [{
          span_id: "span", agent: "", tool: "Process invoice", native_name: "Process invoice", native_type: "TOOL",
          action_type: "native_span", surface: "imported_trace", verdict: "unknown", linked_findings: [], compliance_controls: [],
          parent_state: "missing", parent_span_id: "uncollected-parent", source_scope: { provider: "langfuse", account_id: "111111111111" },
          inventory_binding: { state: "scope_conflict", execution_proven: false },
          cloud_trace: { basis: "source_reported", execution_proven: false, scope_state: "conflict", attributes: {
            "cloud.resource_id": "arn:aws:lambda:us-east-1:222222222222:function:process-invoice:3",
            "aws.request_id": "sdk-request-1", "faas.invocation_id": "execution-attempt-1",
          } },
        }] }],
      } });
      return route.fulfill({ json: {} });
    });
    await page.goto("/traces");
    const disclosure = page.getByText("Cloud identifiers", { exact: true });
    await disclosure.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByText("sdk-request-1", { exact: true })).toBeVisible();
    await expect(page.getByText("execution-attempt-1", { exact: true })).toBeVisible();
    await expect(page.getByText(/Cloud scope conflicts/)).toBeVisible();
    await expect(page.getByRole("link", { name: "Inspect reported inventory entity" })).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.addScriptTag({ content: axeSource });
    const violations = await page.evaluate(async () => {
      const result = await (window as unknown as { axe: { run: () => Promise<{ violations: Array<{ impact: string; id: string }> }> } }).axe.run();
      return result.violations.filter(item => ["serious", "critical"].includes(item.impact));
    });
    expect(violations).toEqual([]);
    await page.screenshot({ path: testInfo.outputPath(`cloud-identifiers-${theme}-${width}.png`), fullPage: true });
  });
}
