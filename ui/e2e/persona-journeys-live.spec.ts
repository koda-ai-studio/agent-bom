import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

/**
 * CISO, AppSec and AI-owner journeys against a running demo-estate API: each
 * metric read on two surfaces must agree, or the page must say why it differs.
 *
 * Opt-in like count-consistency-live: start `agent-bom api --demo-estate`, point
 * the UI dev server at it, and run with AGENT_BOM_E2E_LIVE_API=http://127.0.0.1:<port>.
 */
const LIVE_API = process.env.AGENT_BOM_E2E_LIVE_API ?? "";

test.skip(!LIVE_API, "Set AGENT_BOM_E2E_LIVE_API to a demo-estate API the UI dev server reads");
test.describe.configure({ timeout: 240_000 });

type AttackPaths = { attack_paths: { source: string; vuln_ids: string[]; hops: string[] }[]; nodes: { id: string; label: string }[] };
type Counts = { issues: { critical: number; high: number; total: number } };

async function liveJson<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${LIVE_API}${path}`, { timeout: 120_000 });
  expect(response.ok(), path).toBe(true);
  return (await response.json()) as T;
}

async function open(page: Page, path: string) {
  await page.goto(path, { timeout: 120_000 });
  await page.waitForLoadState("networkidle", { timeout: 120_000 }).catch(() => undefined);
}

test("CISO: overview's #1 risk is Investigation's #1 path, and Open investigation lands on the selected risk", async ({ page, request }) => {
  const queue = await liveJson<AttackPaths>(request, "/v1/graph/attack-paths?limit=5");
  const first = queue.attack_paths[0]!;
  const firstCve = first.vuln_ids[0]!;

  // Side-by-side layout: below it the selected risk opens as a modal drawer over the list.
  await page.setViewportSize({ width: 1440, height: 1000 });
  await open(page, "/");
  await page.getByRole("tab", { name: "Top risks" }).click();
  await expect(page.getByText(/Same order as Investigation/)).toBeVisible({ timeout: 60_000 });
  const rows = page.getByRole("group", { name: "Select a risk" }).getByRole("button");
  await expect(rows.first()).toContainText(firstCve);

  await rows.nth(1).click();
  const secondCve = ((await rows.nth(1).textContent()) ?? "").match(/CVE-\d{4}-\d+/)?.[0];
  expect(secondCve).toBeTruthy();
  const link = page.getByRole("link", { name: /Open investigation/ });
  await expect(link).toHaveAttribute("href", new RegExp(`cve=${secondCve}`));
  await link.click();
  await expect(page).toHaveURL(new RegExp(`/security-graph\\?.*cve=${secondCve}`));
  await expect(page.getByText(new RegExp(`→ ${secondCve}`)).filter({ visible: true }).first()).toBeVisible({ timeout: 120_000 });
});

test("CISO: the trend's latest point is the posture headline, over five or more recorded scans", async ({ page, request }) => {
  const { issues } = await liveJson<Counts>(request, "/v1/posture/counts");
  const trends = await liveJson<{ data_points: { issues: { critical: number; high: number } | null }[] }>(request, "/v1/trends?limit=30&days=90");
  expect(trends.data_points.length).toBeGreaterThanOrEqual(5);
  expect(trends.data_points[0]!.issues).toMatchObject({ critical: issues.critical, high: issues.high });

  await open(page, "/");
  await page.getByText("Changes over time").click();
  await page.getByLabel("History window").selectOption("90");
  const chart = page.getByRole("figure").filter({ hasText: "Critical and high open issues (posture headline basis)" });
  await expect(chart).toBeVisible({ timeout: 60_000 });
  const now = Number(((await chart.locator("p").first().textContent()) ?? "").match(/^\s*([\d,]+)/)?.[1]?.replace(/,/g, "") ?? NaN);
  expect(now).toBe(issues.critical);
  await expect(chart).toContainText(`${trends.data_points.length} snapshots`);
  await expect(chart).not.toContainText("Different basis");
});

test("SOC: the change pair's issue counts are the trend's points for the same two scans", async ({ page, request }) => {
  type Points = { data_points: { scan_id: string; issues: { critical: number; high: number } | null }[] };
  type Change = { sources: { old: { scan_id: string }; new: { scan_id: string }; issue_change: { old: { critical: number; high: number }; new: { critical: number; high: number } } | null }[] };
  const trend = await liveJson<Points>(request, "/v1/trends?limit=30&days=90");
  const changes = await liveJson<Change>(request, "/v1/graph/changes");
  const source = changes.sources[0]!;
  const byScan = new Map(trend.data_points.map((point) => [point.scan_id, point.issues]));
  expect(source.issue_change).not.toBeNull();
  const pick = (counts: { critical: number; high: number }) => ({ critical: counts.critical, high: counts.high });
  expect(pick(source.issue_change!.old)).toEqual(pick(byScan.get(source.old.scan_id)!));
  expect(pick(source.issue_change!.new)).toEqual(pick(byScan.get(source.new.scan_id)!));

  await open(page, "/graph");
  await page.getByTestId("graph-changes-entry").getByRole("button", { name: /changed since/i }).click();
  const line = page.getByTestId("graph-changes-issue-basis").first();
  await expect(line).toBeVisible({ timeout: 120_000 });
  await expect(line).toContainText(`critical ${source.issue_change!.old.critical.toLocaleString()} → ${source.issue_change!.new.critical.toLocaleString()}`);
});

test("CISO: the org card reads its high against the estate-wide headline", async ({ page, request }) => {
  const { issues } = await liveJson<Counts>(request, "/v1/posture/counts");
  const rollup = await liveJson<{ top_level: { entity_type: string; aggregate: { issue_count: number } }[] }>(request, "/v1/graph/rollup");
  const org = rollup.top_level.find((item) => item.entity_type === "org")!;
  await open(page, "/graph");
  const outside = issues.total - org.aggregate.issue_count;
  const comparison = page.getByTestId("graph-scope-estate-comparison").first();
  if (outside > 0) {
    await expect(comparison).toBeVisible({ timeout: 120_000 });
    await expect(comparison).toContainText(`${outside.toLocaleString()} of ${issues.total.toLocaleString()} issues`);
  } else {
    await expect(comparison).toHaveCount(0);
  }
});

test("AI owner: the agent drawer's per-finding credentials equal the exploit story's", async ({ page, request }) => {
  const detail = await liveJson<{ blast_radius: { vulnerability_id: string; package: string; exposed_credentials: string[] }[] }>(request, "/v1/agents/langchain-service");
  const worst = detail.blast_radius.find((row) => row.vulnerability_id === "CVE-2023-36258")!;
  const [name] = worst.package.split("@");
  const story = await liveJson<{ at_risk: { by_kind: { credentials: number } } }>(
    request, `/v1/graph/exploit-story?node=vuln:${worst.vulnerability_id}&package=pkg:pypi:${worst.package}`,
  );
  expect(story.at_risk.by_kind.credentials).toBe(worst.exposed_credentials.length);

  await open(page, "/agents");
  await page.getByText("LangChain Service").first().click();
  const drawer = page.getByRole("dialog");
  const row = drawer.getByRole("listitem").filter({ hasText: worst.vulnerability_id });
  await expect(row).toContainText(`${worst.exposed_credentials.length} credentials exposed by impact`, { timeout: 60_000 });
  await expect(drawer).toContainText(name!);
});

test("AppSec: a workload-reached finding names its reacher, never 'Agent unavailable'", async ({ page }) => {
  await open(page, "/findings");
  await expect(page.getByRole("button", { name: "Investigate" }).first()).toBeVisible({ timeout: 120_000 });
  await expect(page.getByText("Agent unavailable", { exact: true })).toHaveCount(0);
});
