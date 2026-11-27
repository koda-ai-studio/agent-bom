import { test, expect } from "@playwright/test";
import { installAgentScopeFixture } from "./helpers/agent-scope-fixture";

for (const theme of ["light", "dark"]) for (const width of [1440, 390]) {
  test(`agent scope exposes direction, shared MCP and exact findings ${theme} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const { graph, queries, errors } = await installAgentScopeFixture(page);
    await page.goto(`/graph?scan=${graph.scan_id}&rollup=1`);
    const canvas = page.getByTestId("graph-agent-evidence");
    await expect(canvas).toBeVisible();
    if (width === 1440) expect((await page.getByRole("heading", {name: "Investigation", exact: true}).boundingBox())!.y).toBeGreaterThanOrEqual(56);
    if (width === 1440) {
      await expect(canvas.locator('.react-flow__node[data-id="server:filesystem"]')).toBeVisible();
      await expect(canvas.locator('[data-relationship="can_access"]')).toHaveCount(0);
      await expect(canvas.locator('[data-relationship="shares_server"]')).toHaveCount(0);
      await expect(canvas.locator("[data-internet-anchor]")).toHaveCount(1);
      await expect(canvas.locator(".react-flow__node")).toHaveCount(9);
      await expect(canvas.locator(".graph-relationship-label:visible")).toHaveCount(0);
      await expect(canvas.locator('.react-flow__node[data-id="tool:exec"]')).toBeVisible();
      await expect(canvas.locator('.react-flow__node[data-id="cred:aws"]')).toBeVisible();
      const uses = canvas.locator('.react-flow__edge').filter({ has: page.locator('[data-relationship="uses"]') }).first();
      await expect(uses.locator(".react-flow__edge-path")).toHaveCSS("stroke", theme === "dark" ? "rgb(139, 150, 170)" : "rgb(107, 119, 140)");
      await uses.focus();
      await expect(uses).toBeFocused();
      await expect(canvas.locator(".graph-relationship-label").filter({ hasText: "Uses" })).toBeVisible();
      await uses.evaluate(element => (element as HTMLElement).blur());
      for (const path of await canvas.locator('.react-flow__edge-path').all()) {
        const d = await path.getAttribute('d');
        expect(d).toMatch(/^M.*C/);
        expect(d).not.toMatch(/[LQ]/);
      }
      await page.getByText("Exposure and tool context", { exact: true }).click();
      await expect(page.getByRole("button", { name: "Internet-exposed: copilot-portal:2.4.0" })).toBeVisible();
    } else {
      await expect(canvas.locator("li[data-recorded-edge]")).toHaveCount(5);
      await expect(canvas.locator("li").filter({ hasText: "execute_command" })).toContainText("provides tool · Static / configured");
      await expect(canvas.locator("li").filter({ hasText: "AWS_ROLE_SESSION" })).toContainText("exposes cred · Static / configured");
    }
    await page.getByText("Recorded tool control context (1)").click();
    await expect(page.getByRole("button", { name: "default-deny gateway policy", exact: true })).toBeVisible();
    await expect(page.locator("li").filter({ has: page.getByRole("button", { name: "default-deny gateway policy", exact: true }) })).toHaveText("default-deny gateway policy → manages → execute_command");
    await page.screenshot({ path: info.outputPath(`tool-control-${theme}-${width}.png`), fullPage: true });
    await page.getByText("Recorded tool control context (1)").click();
    await page.waitForLoadState("networkidle");
    if (width === 1440) await page.getByText("Exposure and tool context", { exact: true }).click();
    await page.screenshot({ path: info.outputPath(`agent-first-${theme}-${width}.png`), fullPage: true });
    if (width === 1440) {
      await page.getByText(/Relationship evidence \(/).click();
      await expect(page.getByText(/prod-ai-admin → Developer Copilot · can access/)).toBeVisible();
      await expect(page.getByText(/SRE Runbook Agent → filesystem MCP · uses/)).toBeVisible();
      await canvas.getByRole("button", { name: "Expand 1 finding for Developer Copilot" }).click();
    } else await canvas.getByRole("button", { name: "Open 1 finding for Developer Copilot" }).click();
    await expect(page.getByText("Showing 6 assets · 5 recorded connections.")).toBeVisible();
    const findings = page.getByRole("region", { name: "Findings for Developer Copilot" });
    await expect(findings).toContainText("1 open issue");
    await expect(findings).toContainText("CVE-2024-37891");
    await expect(findings.getByRole("button", { name: "Inspect evidence" })).toBeVisible();
    await page.screenshot({ path: info.outputPath(`agent-findings-${theme}-${width}.png`), fullPage: true });
    await findings.getByRole("button", { name: "Close findings" }).click();
    if (width === 1440) await canvas.locator('.react-flow__node[data-id="server:filesystem"]').click();
    else await canvas.getByRole("button", { name: "filesystem MCP", exact: true }).first().click();
    await expect.poll(() => queries.at(-1)?.roots).toEqual(["server:filesystem"]);
    await expect(page.getByText("execute_command", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("AWS_ROLE_SESSION", { exact: true }).first()).toBeVisible();
    if (width === 1440) {
      const credential = page.locator('.react-flow__edge[data-id="server:filesystem->cred:aws:exposes_cred"] .react-flow__edge-path');
      await expect(credential).toHaveCSS("stroke-dasharray", "none");
      await expect(page.getByRole("region", {name: "Capability risk assessment"})).toBeVisible();
      expect((await page.getByRole("heading", {name: "Investigation", exact: true}).boundingBox())!.y).toBeGreaterThanOrEqual(56);
    }
    await page.screenshot({ path: info.outputPath(`server-expanded-${theme}-${width}.png`), fullPage: true });
    await page.goto(`/graph?scan=${graph.scan_id}&rollup=1`);
    if (width === 1440) await page.getByText("Exposure and tool context", { exact: true }).click();
    await page.getByText("Recorded tool control context (1)").click();
    await page.locator("details").filter({ has: page.getByText("Recorded tool control context (1)", {exact: true}) }).getByRole("button", { name: "execute_command", exact: true }).click();
    await expect.poll(() => queries.at(-1)?.roots).toEqual(["tool:exec"]);
    await expect(page.getByText("default-deny gateway policy", { exact: true }).first()).toBeVisible();
    if (width === 1440) {
      await expect(page.getByText("Shell command execution", { exact: true })).toBeVisible();
      await expect(page.getByText("2026-06-03 20:30 UTC", { exact: true }).first()).toBeVisible();
      for (const path of await page.locator(".react-flow__edge-path").all()) {
        await expect(path).toHaveAttribute("marker-end", /.+/);
        expect(await path.evaluate(element => {
          const reference = element.getAttribute("marker-end")!.replace(/^url\(['"]?#/, "").replace(/['"]?\)$/, "");
          const marker = document.getElementById(reference) as unknown as SVGMarkerElement;
          const shape = marker.querySelector<SVGGraphicsElement>("polyline")!;
          const scale = (element as SVGPathElement).getScreenCTM()!.a;
          return shape.getBBox().width / marker.viewBox.baseVal.width * marker.markerWidth.baseVal.value * scale;
        })).toBeGreaterThanOrEqual(5.5);
      }
    }
    await page.screenshot({ path: info.outputPath(`tool-expanded-${theme}-${width}.png`), fullPage: true });
    expect(errors).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}
