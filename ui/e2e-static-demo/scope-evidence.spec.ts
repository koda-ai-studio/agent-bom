import { expect, test } from "@playwright/test";
import path from "node:path";
import { startStaticDemoServer } from "../scripts/static-demo-server.mjs";

const basePath = "/agent-bom/demo";
let server: { origin: string; close: () => Promise<unknown> };
test.beforeAll(async () => { server = await startStaticDemoServer(path.resolve(process.cwd(), process.env.STATIC_DEMO_OUT ?? "out"), basePath); });
test.afterAll(async () => { await server.close(); });

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`bundled scope findings retain recorded direction and exact issue ${theme} ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(`${server.origin}${basePath}/graph?scan=scan-proof-ai-platform&rollup=1`, { waitUntil: "networkidle" });
    const canvas = page.getByTestId("graph-agent-evidence");
    await expect(canvas).toBeVisible();
    await expect(canvas.getByText("filesystem MCP", { exact: true }).first()).toBeVisible();
    if (width === 1440) {
      await page.getByText(/Relationship evidence \(/).click();
      await expect(page.getByText(/prod-ai-admin → Developer Copilot · can access/)).toBeVisible();
      await canvas.getByRole("button", { name: "Inspect 1 finding in the scope of Developer Copilot" }).click();
    } else {
      await expect(canvas.locator("li").filter({ hasText: "prod-ai-admin" })).toContainText("prod-ai-admin→Developer Copilot");
      await canvas.getByRole("button", { name: "Open 1 finding for Developer Copilot" }).click();
    }
    const findings = page.getByRole("region", { name: "Findings for Developer Copilot" });
    await expect(findings).toContainText("1 open issue");
    await expect(findings).toContainText("CVE-2024-37891");
    await expect(findings.getByRole("button", { name: "Inspect evidence" })).toBeVisible();
    expect(errors).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}
