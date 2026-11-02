import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  pathname: "/",
  session: null as Record<string, unknown> | null,
  scanSources: [] as string[],
}));

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode; [key: string]: unknown }) => (
    <a href={href} {...rest}>{children}</a>
  ),
}));
vi.mock("next/navigation", () => ({ usePathname: () => state.pathname }));
vi.mock("@/components/auth-gate", () => ({
  AuthGate: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({
    session: state.session,
    loading: false,
    error: null,
    refresh: vi.fn(),
    signOut: vi.fn(),
    hasCapability: () => false,
  }),
}));
vi.mock("@/hooks/use-demo-mode", () => ({ useDemoMode: () => ({ isDemoMode: false, loading: false }) }));
vi.mock("@/lib/api", () => ({
  api: {
    getPostureCounts: vi.fn(async () => ({
      critical: 0, high: 0, medium: 0, low: 0, total: 0, compound_issues: 0,
      deployment_mode: "hybrid", scan_count: 1, has_local_scan: true,
      scan_sources: state.scanSources,
    })),
    health: vi.fn(async () => ({ status: "ok", version: "0.113.0" })),
  },
}));

import { AppShell } from "@/components/app-shell";
import SettingsPage from "@/app/settings/page";
import { api } from "@/lib/api";

const anonymous = {
  authenticated: true, auth_required: false, auth_method: null, subject: null,
  role: "admin", role_summary: null, tenant_id: "default", memberships: [],
};
const signedIn = {
  authenticated: true, auth_required: true, auth_method: "oidc", subject: "ops@example.test",
  role: "viewer", role_summary: null, tenant_id: "acme", memberships: [],
};

function renderRoute(pathname: string, page: React.ReactNode = <div>page</div>) {
  state.pathname = pathname;
  return render(<AppShell>{page}</AppShell>);
}

async function chipName() {
  const summary = await screen.findByLabelText(/^Account menu: /);
  await waitFor(() => expect(api.getPostureCounts).toHaveBeenCalled());
  return summary;
}

beforeEach(() => {
  vi.mocked(api.getPostureCounts).mockClear();
  window.history.replaceState(null, "", "/");
});
afterEach(() => window.history.replaceState(null, "", "/"));

describe("header identity chip reads the same demo signal as the demo-data banner", () => {
  it.each(["/", "/graph", "/findings", "/compliance"])("names an anonymous reader of demo data a demo visitor on %s", async (route) => {
    state.session = anonymous;
    state.scanSources = ["demo-scan", "fleet-sync"];
    renderRoute(route);
    const summary = await chipName();
    await waitFor(() => expect(summary).toHaveAttribute("aria-label", "Account menu: Demo visitor"));
    expect(document.getElementById("demo-estate-watermark")).not.toBeNull();
    expect(screen.queryByText("Unauthenticated access")).toBeNull();
    expect(api.getPostureCounts).toHaveBeenCalledTimes(1);
  });

  it("keeps the honest unauthenticated label on a real no-auth deployment", async () => {
    state.session = anonymous;
    state.scanSources = ["local", "fleet-sync"];
    renderRoute("/graph");
    const summary = await chipName();
    await waitFor(() => expect(api.getPostureCounts).toHaveBeenCalledTimes(1));
    expect(summary).toHaveAttribute("aria-label", "Account menu: Unauthenticated access");
    expect(document.getElementById("demo-estate-watermark")).toBeNull();
  });

  it("never relabels a signed-in principal on demo data", async () => {
    state.session = signedIn;
    state.scanSources = ["demo-estate"];
    renderRoute("/graph");
    const summary = await chipName();
    await waitFor(() => expect(document.getElementById("demo-estate-watermark")).not.toBeNull());
    expect(summary).toHaveAttribute("aria-label", "Account menu: ops@example.test");
  });

  it("presents the demo visitor in capture mode, where the banner is shown for the screenshot fixtures", async () => {
    window.history.replaceState(null, "", "/graph?capture=1");
    state.session = anonymous;
    state.scanSources = [];
    renderRoute("/graph");
    const summary = await chipName();
    await waitFor(() => expect(document.getElementById("demo-estate-watermark")).not.toBeNull());
    await waitFor(() => expect(summary).toHaveAttribute("aria-label", "Account menu: Demo visitor"));
  });

  it("shows the same identity in the settings page body, without a second counts read", async () => {
    state.session = anonymous;
    state.scanSources = ["demo-scan"];
    renderRoute("/settings", <SettingsPage />);
    const summary = await chipName();
    await waitFor(() => expect(summary).toHaveAttribute("aria-label", "Account menu: Demo visitor"));
    expect(screen.getAllByText("Demo visitor").length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText("Unauthenticated access")).toBeNull();
    expect(api.getPostureCounts).toHaveBeenCalledTimes(1);
  });
});
