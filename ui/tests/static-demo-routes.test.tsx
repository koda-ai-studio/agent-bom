import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});

function manifest(routes: string[]) {
  return vi.fn(async () => new Response(JSON.stringify({ schema_version: "static-demo-routes.v1", routes }), { status: 200 }));
}

describe("static demo route manifest", () => {
  it("answers whether a path, with or without a query, is part of the demo", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    vi.stubEnv("NEXT_PUBLIC_BASE_PATH", "/agent-bom/demo");
    const fetchMock = manifest(["/", "/findings"]);
    vi.stubGlobal("fetch", fetchMock);
    const { loadStaticDemoRoutes, isStaticDemoRoute } = await import("@/lib/static-demo-routes");
    const routes = (await loadStaticDemoRoutes())!;
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toBe("/agent-bom/demo/demo-data/routes.json");
    expect(isStaticDemoRoute(routes, "/findings?lens=trust")).toBe(true);
    expect(isStaticDemoRoute(routes, "/findings/")).toBe(true);
    expect(isStaticDemoRoute(routes, "/identity")).toBe(false);
  });

  it("shows the not-in-demo panel instead of a page with no sample data", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    vi.stubGlobal("fetch", manifest(["/"]));
    const { StaticDemoRouteGate } = await import("@/components/static-demo-route-gate");
    render(<StaticDemoRouteGate pathname="/identity"><p>identity page</p></StaticDemoRouteGate>);
    const panel = await screen.findByRole("region", { name: "Not part of the demo" });
    expect(panel).toHaveTextContent("This page isn't part of the read-only demo — install agent-bom to see it on your own data");
    expect(screen.getByRole("link", { name: /quick start/i })).toHaveAttribute("href", expect.stringContaining("getting-started/quickstart"));
    expect(screen.queryByText("identity page")).toBeNull();
  });

  it("renders recorded pages, and every page outside the demo build", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    vi.stubGlobal("fetch", manifest(["/findings"]));
    const { StaticDemoRouteGate } = await import("@/components/static-demo-route-gate");
    render(<StaticDemoRouteGate pathname="/findings"><p>findings page</p></StaticDemoRouteGate>);
    await waitFor(() => expect(screen.getByText("findings page")).toBeInTheDocument());
    vi.unstubAllEnvs();
    vi.resetModules();
    const fresh = await import("@/components/static-demo-route-gate");
    render(<fresh.StaticDemoRouteGate pathname="/identity"><p>normal build</p></fresh.StaticDemoRouteGate>);
    expect(screen.getByText("normal build")).toBeInTheDocument();
  });
});
