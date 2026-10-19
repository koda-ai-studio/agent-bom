import { expect, test } from "@playwright/test";
const lanes = ["vulnerabilities", "cloud", "iac", "secrets", "identity", "data", "other"];
const titles = ["CVE-2026-1234", "Failed CIS 1.4 — Limit administrative access", "Restrict Kubernetes role bindings", "Exposed credential reference", "Unused administrative permissions", "Sensitive customer records", "Prompt policy needs review"];
const counts = Object.fromEntries(lanes.map((lane, index) => [lane, index + 1]));
for (const theme of ["light", "dark"] as const) {
  for (const width of [390, 1280, 1440, 1920]) {
    test(`${theme} ${width}: lanes, evidence and responsive layout`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
      await page.route("**/v1/**", async (route) => {
        const url = new URL(route.request().url());
        if (url.pathname.endsWith("/auth/me")) return route.fulfill({ json: { authenticated: true, auth_required: false, role: "analyst", tenant_id: "lane-fixture", memberships: [], role_summary: { role: "analyst", ui_role: "analyst", capabilities: ["findings.read", "findings.write"] } } });
        if (url.pathname.endsWith("/findings/triage")) return route.fulfill({ json: { triage: [] } });
        if (url.pathname.endsWith("/findings")) {
          const lane = url.searchParams.get("lane") || "vulnerabilities";
          const index = lanes.indexOf(lane);
          const finding = { id: `finding-${lane}`, finding_id: `finding-${lane}`, lane, title: titles[index], severity: "high", severity_source: lane === "cloud" ? "benchmark-mapped" : "rule", source: lane === "iac" ? "IAC_SCAN" : "fixture", finding_type: lane === "vulnerabilities" ? "CVE" : "CIS_FAIL", finding_class: lane === "vulnerabilities" ? "vulnerability" : "misconfiguration", cve_id: lane === "vulnerabilities" ? titles[index] : null,
            asset: { name: lane === "iac" ? "main.tf" : "production-service", asset_type: lane === "iac" ? "iac_resource" : "cloud_resource" }, provider: "aws", account_ref: "aws:123456789012", remediation_guidance: "Remove unused administrative grants and repeat the check.", evidence: { repository_relative_path: "infra/kubernetes/production/main.tf", line_number: 42, rule_id: lane === "iac" ? "K8S-RBAC-005" : "1.4", expected: "Scoped permissions", observed: "Administrative grant" } };
          const findings = Array.from({ length: index + 1 }, (_, occurrence) => ({ ...finding, id: `${finding.id}-${occurrence}`, finding_id: `${finding.id}-${occurrence}`, title: lane === "cloud" ? `Failed CIS 1.${occurrence + 4} — Limit administrative access` : occurrence === 0 ? finding.title : `${finding.title} · check ${occurrence + 1}`, evidence: { ...finding.evidence, rule_id: lane === "cloud" ? `1.${occurrence + 4}` : finding.evidence.rule_id }, occurrence_count: lane === "cloud" && occurrence === 0 ? 2 : 1, occurrences: lane === "cloud" && occurrence === 0 ? [{ finding_id: "cloud-resource-1", asset: { name: "production-service" } }, { finding_id: "cloud-resource-2", asset: { name: "analytics-service" } }] : [] }));
          return route.fulfill({ json: { findings, total: findings.length, facets: { severity: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, unknown: 0 }, lane: counts }, has_more: false } });
        }
        return route.fulfill({ json: { jobs: [], agents: [], findings: [], total: 0 } });
      });
      await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
      await page.goto("/findings");
      await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
      await expect(page.getByRole("tab", { name: "Vulnerabilities 1", exact: true })).toHaveAttribute("aria-selected", "true");
      await page.getByRole("tab", { name: "Cloud config 2", exact: true }).click();
      await expect(page).toHaveURL(/lane=cloud/);
      await expect(page.getByText(titles[1]!, { exact: true })).toBeVisible();
      await expect(page.getByLabel("Check result: Failed").first()).toBeVisible();
      await expect(page.getByText("Agent unavailable", { exact: true })).toHaveCount(0);
      await page.screenshot({ path: testInfo.outputPath(`cloud-${theme}-${width}.png`), fullPage: true });
      await page.getByRole("tab", { name: "IaC 3", exact: true }).click();
      await expect(page.getByText("infra/kubernetes/production/main.tf:42").first()).toBeVisible();
      await expect(page).toHaveURL(/lane=iac/);
      await page.reload();
      await expect(page.getByRole("tab", { name: "IaC 3", exact: true })).toHaveAttribute("aria-selected", "true");
      await page.screenshot({ path: testInfo.outputPath(`iac-${theme}-${width}.png`), fullPage: true });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.getByRole("button", { name: "Investigate", exact: true }).first().click();
      await expect(page.getByRole("dialog")).toBeVisible();
    });
  }
}
