import { readFileSync } from "node:fs";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

const php2shell = JSON.parse(readFileSync(path.join(__dirname, "..", "tests", "fixtures", "php2shell-affected.json"), "utf8"));

async function baseline(page: Page, theme: string) {
  await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
  await page.route("**/v1/**", (route) => route.fulfill({ json: {} }));
  await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/version", (route) => route.fulfill({ json: { version: "0.110.0" } }));
  await page.route("**/v1/auth/me", (route) => route.fulfill({ json: {
    authenticated: true, auth_required: false, configured_modes: [], recommended_ui_mode: "no_auth",
    role: "admin", subject: null, auth_method: null, memberships: [], tenant_id: "fixture",
    role_summary: { role: "admin", ui_role: "admin", display_name: "Admin", capabilities: ["policy.manage"] },
  } }));
  await page.route("**/v1/intel/advisories/*/affected?**", (route) => route.fulfill({ json: php2shell }));
  await page.route("**/v1/intel/operator-advisories", (route) => route.request().method() === "POST"
    ? route.fulfill({ status: 422, json: { detail: [{ loc: ["body", "affected", 0], msg: "Value error, introduced must precede fixed", type: "value_error" }] } })
    : route.fulfill({ json: {
      advisories: [{ id: "CVE-2026-109618", aliases: ["CVE-2026-109619"], summary: php2shell.advisory.summary, severity: "critical", references: [], affected: [{ cpe_product: "php:php", ranges: [], versions: [] }], updated_at: "2026-10-23T09:00:00+00:00" }],
      provenance: "operator_advisory",
      rematch: { last_run: "2026-10-24T01:00:00+00:00" },
    } }));
}

async function noPageOverflow(page: Page) {
  await expect(page.locator("#main-content")).toHaveCSS("padding-left", "0px");
  await expect.poll(() => page.evaluate(() => document.querySelector("#main-content")!.getBoundingClientRect().left)).toBeLessThanOrEqual(1);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
}

for (const theme of ["light", "dark"]) {
  test(`advisory affected assets render the PHP2Shell answer in ${theme}`, async ({ page }, testInfo) => {
    await baseline(page, theme);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/advisories?id=CVE-2026-109618");
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    const table = page.getByRole("table", { name: "Affected assets" });
    await expect(table).toBeVisible();
    await expect(page.getByRole("list", { name: "Verdict summary" }).getByRole("listitem")).toHaveText([
      "1Affected", "1Possibly affected (distro)", "1Not affected", "1Clean scanned",
    ]);
    await expect(table.getByText("Possibly affected — verify distro advisory")).toBeVisible();
    await expect(table.getByRole("link", { name: "Blast radius for php 8.3.30 on php:8.3.30-cli" }))
      .toHaveAttribute("href", /\/security-graph\?lens=attack-path&scan=scan-php-8\.3\.30&node=pkg%3Ageneric%2Fphp%408\.3\.30/);
    await page.screenshot({ path: testInfo.outputPath(`advisories-affected-${theme}-1440.png`), fullPage: true });

    await page.setViewportSize({ width: 390, height: 844 });
    await noPageOverflow(page);
    await page.screenshot({ path: testInfo.outputPath(`advisories-affected-${theme}-390.png`), fullPage: true });

    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/advisories?tab=declare");
    await expect(page.getByRole("listitem", { name: "CVE-2026-109618" })).toBeVisible();
    await page.getByLabel("Advisory ID").fill("CVE-2026-109618");
    await page.getByLabel("Summary").fill("php2shell");
    await page.getByRole("radio", { name: "CPE product" }).check();
    await page.getByLabel("CPE product (vendor:product)").fill("php:php");
    await page.getByLabel("Introduced").fill("8.3.36");
    await page.getByLabel("Fixed").fill("8.3.0");
    await page.getByRole("button", { name: "Declare advisory" }).click();
    await expect(page.getByRole("alert", { name: "The server rejected this advisory" })).toContainText("Affected product 1: introduced must precede fixed");
    await page.screenshot({ path: testInfo.outputPath(`advisories-declare-${theme}-1440.png`), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await noPageOverflow(page);
    await page.screenshot({ path: testInfo.outputPath(`advisories-declare-${theme}-390.png`), fullPage: true });
  });
}
