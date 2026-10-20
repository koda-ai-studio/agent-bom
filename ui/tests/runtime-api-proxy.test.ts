import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { _resetUpstreamReadiness, proxyApiRequest, runtimeApiOrigin } from "@/server/runtime-api-proxy";

const upstreamUp = () => vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
beforeEach(() => { _resetUpstreamReadiness(); vi.stubGlobal("fetch", upstreamUp()); });
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe("runtime API routing", () => {
  it("uses the runtime server destination without changing browser origin", async () => {
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend-a:8422");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://legacy:8422");
    const req = new NextRequest("http://ui:3000/v1/auth/me?scope=one", { headers: { cookie: "session=opaque", authorization: "Bearer opaque" } });
    expect((await proxyApiRequest(req)).headers.get("x-middleware-rewrite")).toBe("http://backend-a:8422/v1/auth/me?scope=one");
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend-b:8423");
    expect((await proxyApiRequest(req)).headers.get("x-middleware-rewrite")).toBe("http://backend-b:8423/v1/auth/me?scope=one");
  });
  it("preserves the legacy runtime variable and local default", () => {
    vi.stubEnv("AGENT_BOM_API_URL", "");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://legacy:8422/");
    expect(runtimeApiOrigin()).toBe("http://legacy:8422");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "");
    expect(runtimeApiOrigin()).toBe("http://localhost:8422");
  });
  it.each(["file:///etc/passwd", "http://user:secret@host", "http://host/path", "http://host?url=evil", "http://host/#fragment"])("rejects invalid destination %s", async (value) => {
    vi.stubEnv("AGENT_BOM_API_URL", value);
    expect(() => runtimeApiOrigin()).toThrow("Invalid server API origin");
    const response = await proxyApiRequest(new NextRequest("http://ui:3000/health"));
    expect(response.status).toBe(503);
  });
  it.each(["/v1/auth/me", "/health", "/version", "/ws/live"])("routes %s only to the configured backend", async (path) => {
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend:8422");
    const response = await proxyApiRequest(new NextRequest(`http://ui:3000${path}?next=https://other.example`));
    expect(response.headers.get("x-middleware-rewrite")).toBe(`http://backend:8422${path}?next=https://other.example`);
  });
  it.each(["/", "/v10/private", "/health-extra", "/_next/static/app.js"])("does not route unrelated %s", async (path) => {
    expect((await proxyApiRequest(new NextRequest(`http://ui:3000${path}`))).headers.has("x-middleware-rewrite")).toBe(false);
  });

  it("answers 503 with Retry-After while the API is not yet accepting connections", async () => {
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend:8422");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } })));
    const response = await proxyApiRequest(new NextRequest("http://ui:3000/v1/auth/me"));
    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("2");
    expect(response.headers.has("x-middleware-rewrite")).toBe(false);
    expect(await response.json()).toMatchObject({ error: { code: "API_STARTING" }, retry_after_seconds: 2 });
  });

  it("probes readiness once, then forwards without a probe per request", async () => {
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend:8422");
    const probe = upstreamUp();
    vi.stubGlobal("fetch", probe);
    for (const path of ["/v1/auth/me", "/v1/findings", "/health"]) {
      expect((await proxyApiRequest(new NextRequest(`http://ui:3000${path}`))).headers.get("x-middleware-rewrite")).toBe(`http://backend:8422${path}`);
    }
    expect(probe).toHaveBeenCalledTimes(1);
    expect(probe).toHaveBeenCalledWith("http://backend:8422/health", expect.objectContaining({ cache: "no-store" }));
  });

  it("forwards a slow API rather than calling it starting", async () => {
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend:8422");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new DOMException("timed out", "TimeoutError")));
    const response = await proxyApiRequest(new NextRequest("http://ui:3000/v1/findings"));
    expect(response.headers.get("x-middleware-rewrite")).toBe("http://backend:8422/v1/findings");
  });

  it("recovers as soon as the API accepts connections", async () => {
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend:8422");
    const refused = Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });
    vi.stubGlobal("fetch", vi.fn().mockRejectedValueOnce(refused).mockResolvedValue(new Response("ok")));
    expect((await proxyApiRequest(new NextRequest("http://ui:3000/v1/auth/me"))).status).toBe(503);
    expect((await proxyApiRequest(new NextRequest("http://ui:3000/v1/auth/me"))).headers.get("x-middleware-rewrite")).toBe("http://backend:8422/v1/auth/me");
  });
});
