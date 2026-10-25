import { afterEach, describe, expect, it, vi } from "vitest";

async function loadTransport() {
  vi.resetModules();
  return import("@/lib/api-transport");
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("static demo transport", () => {
  it("maps an API path to a flat file name that ignores the query", async () => {
    const { staticDemoDataKey } = await import("@/lib/static-demo-key.mjs");
    expect(staticDemoDataKey("/v1/graph?scan_id=a&limit=5")).toBe("v1_graph");
    expect(staticDemoDataKey("/v1/inventory/assets/pkg%3Anext")).toBe("v1_inventory_assets_pkg_3Anext");
    expect(staticDemoDataKey("/health")).toBe("health");
    expect(staticDemoDataKey("/v1/../../etc/passwd")).not.toContain("/");
  });

  it("reads GETs from the shipped JSON under the base path, never the API", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    vi.stubEnv("NEXT_PUBLIC_BASE_PATH", "/agent-bom/demo");
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { get } = await loadTransport();
    await expect(get("/v1/overview")).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = String((fetchMock.mock.calls[0] as unknown[])[0]);
    expect(url.startsWith("/agent-bom/demo/demo-data/v1_overview.json")).toBe(true);
  });

  it("reads the query-specific file first and falls back to the path file", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    const { staticDemoQueryKey } = await import("@/lib/static-demo-key.mjs");
    expect(staticDemoQueryKey("/v1/inventory/summary?type=package")).toBe(staticDemoQueryKey("/v1/inventory/summary?type=package"));
    expect(staticDemoQueryKey("/v1/a?x=1&y=2")).toBe(staticDemoQueryKey("/v1/a?y=2&x=1"));
    expect(staticDemoQueryKey("/v1/a?x=1")).not.toBe(staticDemoQueryKey("/v1/a?x=2"));
    expect(staticDemoQueryKey("/v1/a")).toBeNull();
    const fetchMock = vi.fn(async (url: string) => url.includes("__q")
      ? new Response("", { status: 404 })
      : new Response(JSON.stringify({ scope: "all" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { get } = await loadTransport();
    await expect(get("/v1/inventory/summary?type=package")).resolves.toEqual({ scope: "all" });
    expect(fetchMock.mock.calls.map((call) => String((call as unknown[])[0]).split("?")[0])).toEqual([
      `/demo-data/${staticDemoQueryKey("/v1/inventory/summary?type=package")}.json`,
      "/demo-data/v1_inventory_summary.json",
    ]);
  });

  it("refuses writes with the read-only message and makes no request", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { post } = await loadTransport();
    const error = await post("/v1/scan", { targets: [] }).catch((caught: unknown) => caught);
    expect(String((error as Error).message)).toMatch(/read-only demo/);
    // Not a permission error: forms would otherwise tell the viewer they need the admin role.
    const { ApiForbiddenError } = await import("@/lib/api-errors");
    expect(error).not.toBeInstanceOf(ApiForbiddenError);
    expect((error as Error).name).toBe("StaticDemoReadOnlyError");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports a missing demo file as not found, not a network failure", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 404, statusText: "Not Found" })));
    const { get } = await loadTransport();
    await expect(get("/v1/not-recorded")).rejects.toMatchObject({ name: "ApiNotFoundError", status: 404 });
  });

  it("leaves the normal API path untouched when the flag is off", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { get } = await loadTransport();
    await get("/v1/overview");
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toBe("/v1/overview");
  });
});
