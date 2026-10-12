import { expect, test } from "@playwright/test";
import { routeBaseline } from "./fixtures/route-catalog";

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`account, preferences and explicit logout ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => { if (!localStorage.getItem("agent-bom-theme")) localStorage.setItem("agent-bom-theme", value); }, theme);
    await routeBaseline(page);
    let signedIn = true;
    let devExchanges = 0;
    await page.route("**/v1/auth/me", route => route.fulfill({ json: {
      authenticated: signedIn, auth_required: true, configured_modes: ["api_key"], recommended_ui_mode: "session_api_key",
      auth_method: signedIn ? "browser_session" : null, subject: signedIn ? "synthetic-operations-key" : null,
      tenant_id: "synthetic-staging", role: signedIn ? "admin" : null,
      role_summary: signedIn ? { display_name: "Admin", capabilities: ["inventory.read", "scan.run", "keys.manage", "audit.read", "policy.manage"] } : null,
      memberships: [],
    } }));
    await page.route("**/v1/auth/dev-session", route => { devExchanges++; return route.fulfill({ status: 404 }); });
    await page.route("**/v1/auth/session", route => {
      if (route.request().method() === "DELETE") { signedIn = false; return route.fulfill({ status: 204 }); }
      signedIn = true; return route.fulfill({ status: 204 });
    });
    await page.goto("/settings");
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
    await expect(page.getByText("This identity belongs to an API key.", { exact: false })).toBeVisible();
    await expect(page.getByText("synthetic-staging", { exact: true }).first()).toBeVisible();
    await expect(page.getByRole("combobox", { name: /workspace/i })).toHaveCount(0);
    await page.getByLabel(/^Account menu:/).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByLabel("Account details")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByLabel(/^Account menu:/)).toBeFocused();
    await page.screenshot({ path: testInfo.outputPath(`settings-${theme}-${width}.png`), fullPage: true });
    await page.emulateMedia({ colorScheme: "light" });
    await page.getByRole("button", { name: "System", exact: true }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.emulateMedia({ colorScheme: "dark" });
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole("heading", { name: "Signed out", exact: true })).toBeVisible();
    await page.emulateMedia({ colorScheme: "light" });
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.reload();
    await expect(page.getByRole("heading", { name: "Signed out", exact: true })).toBeVisible();
    await page.emulateMedia({ colorScheme: "dark" });
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    expect(devExchanges).toBe(0);
    await page.getByRole("button", { name: "Continue to sign in" }).click();
    await page.getByLabel("API key", { exact: true }).fill("synthetic-credential");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page).toHaveURL(/\/settings$/);
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
  });
}

for (const role of ["viewer", "analyst", "admin"] as const) {
  test(`${role} signs in to scoped evidence and sees only authorized settings`, async ({ page }) => {
    await routeBaseline(page);
    let authenticated = false;
    const capabilities = ["inventory.read", ...(role !== "viewer" ? ["scan.run"] : []), ...(role === "admin" ? ["keys.manage", "audit.read", "policy.manage"] : [])];
    await page.route("**/v1/auth/me", route => route.fulfill({ json: {
      authenticated, auth_required: true, configured_modes: ["api_key"], auth_method: authenticated ? "browser_session" : null,
      subject: authenticated ? `synthetic-${role}-key` : null, tenant_id: "synthetic-tenant", role: authenticated ? role : null,
      role_summary: authenticated ? { display_name: role, capabilities } : null, memberships: [],
    } }));
    await page.route("**/v1/auth/session", route => { authenticated = route.request().method() !== "DELETE"; return route.fulfill({ status: 204 }); });
    await page.route("**/v1/agents", route => route.fulfill({ json: { count: 1, agents: [{
      name: "Synthetic scoped agent", agent_type: "custom", status: "configured", config_path: "synthetic-fixture",
      mcp_servers: [{ name: "synthetic-mcp", transport: "stdio", command: "synthetic", packages: [], tools: [], credential_env_vars: [] }],
    }] } }));
    await page.goto("/agents");
    await expect(page).toHaveURL(/\/login/);
    await page.getByLabel("API key", { exact: true }).fill(`synthetic-${role}-credential`);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page).toHaveURL(/\/agents$/);
    await expect(page.getByTestId("agents-configured-table").getByText("Synthetic scoped agent", { exact: true })).toBeVisible();
    await page.getByLabel(/^Account menu:/).click();
    await expect(page.getByLabel("Account details")).toContainText("synthetic-tenant");
    await expect(page.getByLabel("Account details").getByRole("link", { name: "Access & keys" })).toHaveCount(role === "admin" ? 1 : 0);
    await page.getByRole("link", { name: "Profile & settings" }).click();
    const controls = page.getByRole("region", { name: "Deployment & administration" });
    if (role === "viewer") await expect(controls).toHaveCount(0);
    else await expect(controls.getByRole("link", { name: /Connections/ })).toBeVisible();
    await expect(page.getByText("This identity belongs to an API key.", { exact: false })).toBeVisible();
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Signed out", exact: true })).toBeVisible();
    await expect(page.getByLabel(/^Account menu:/)).toHaveCount(0);
  });
}
