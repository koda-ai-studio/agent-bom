import { expect, test } from "@playwright/test";
import path from "node:path";
import { readFile } from "node:fs/promises";
import { startStaticDemoServer } from "../scripts/static-demo-server.mjs";
const basePath = "/agent-bom/demo";
let server: { origin: string; close: () => Promise<unknown> };
test.beforeAll(async () => { server = await startStaticDemoServer(path.resolve(process.cwd(), process.env.STATIC_DEMO_OUT ?? "out"), basePath); });
test.afterAll(async () => { await server.close(); });
for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`brief preview, downloads and scope in ${theme} at ${width}px`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.goto(`${server.origin}${basePath}/brief`);
    await expect(page.getByRole("heading", { name: "Executive brief", exact: true })).toBeVisible();
    await expect(page.getByText("Sample data", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Download signed pack" })).toBeDisabled();
    await expect(page.getByRole("link", { name: "Investigate this snapshot" })).toHaveAttribute("href", /scan=/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath(`brief-${theme}-${width}.png`), fullPage: true });
    for (const format of ["JSON", "Markdown"]) {
      const event = page.waitForEvent("download");
      await page.getByRole("button", { name: `Download ${format}` }).click();
      const download = await event;
      const content = await readFile((await download.path())!, "utf8");
      if (format === "JSON") {
        const brief = JSON.parse(content);
        expect(brief.sample_data).toBe(true); expect(brief.document_type).toBe("executive-brief");
        expect(brief.exposure_paths.scan_id).toBe(brief.scope.exposure_scan_id);
      } else {
        expect(content).toContain("Sample data"); expect(content).toContain("Collection coverage: unknown");
        expect(content).toContain("independent_source_reads");
      }
    }
  });
}
