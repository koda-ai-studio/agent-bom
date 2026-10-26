import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { _clearApiCacheForTests } from "@/lib/api";
import { get, post } from "@/lib/api-transport";
import { ApiNetworkError, ApiRateLimitError, ApiServerError, ApiValidationError, isApiBusyError } from "@/lib/api-errors";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

beforeEach(() => _clearApiCacheForTests());
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); _clearApiCacheForTests(); });

describe("idempotent GET retry", () => {
  it("retries once after a reset connection and returns the second answer", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNRESET" } }))
      .mockResolvedValueOnce(json({ findings: [] }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(get("/v1/findings")).resolves.toEqual({ findings: [] });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("retries once when the dev proxy reports a dropped upstream as a non-JSON 500", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("Internal Server Error", { status: 500 }))
      .mockResolvedValueOnce(json({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(get("/v1/findings?page=1")).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("retries a gateway failure once, then surfaces the error", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("", { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(get("/v1/findings?page=2")).rejects.toBeInstanceOf(ApiServerError);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("never retries an API-reported 500, a client error, a caller abort, or a write", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ detail: "boom" }, 500))
      .mockResolvedValueOnce(json({ detail: "bad" }, 422))
      .mockResolvedValueOnce(json({ detail: "503 Service Unavailable" }, 503));
    vi.stubGlobal("fetch", fetchMock);
    await expect(get("/v1/a")).rejects.toBeInstanceOf(ApiServerError);
    await expect(get("/v1/b")).rejects.toBeInstanceOf(ApiValidationError);
    // The API itself said it is unavailable: an answer, not a dropped connection.
    await expect(get("/v1/auth/me")).rejects.toBeInstanceOf(ApiServerError);
    expect(fetchMock).toHaveBeenCalledTimes(3);

    const controller = new AbortController();
    controller.abort();
    const aborting = vi.fn().mockRejectedValue(new DOMException("aborted", "AbortError"));
    vi.stubGlobal("fetch", aborting);
    await expect(get("/v1/c", { signal: controller.signal })).rejects.toBeInstanceOf(ApiNetworkError);
    expect(aborting).toHaveBeenCalledTimes(1);

    const writes = vi.fn().mockRejectedValue(new TypeError("fetch failed"));
    vi.stubGlobal("fetch", writes);
    await expect(post("/v1/d", {})).rejects.toBeInstanceOf(ApiNetworkError);
    expect(writes).toHaveBeenCalledTimes(1);
  });

  it("waits Retry-After and retries once when the API says a 503 is retryable", async () => {
    vi.useFakeTimers();
    const rotating = new Response(JSON.stringify({ detail: { code: "current_estate_generation_rotating", message: "retry" } }),
      { status: 503, headers: { "Content-Type": "application/json", "Retry-After": "1" } });
    const fetchMock = vi.fn().mockResolvedValueOnce(rotating).mockResolvedValueOnce(json({ nodes: [] }));
    vi.stubGlobal("fetch", fetchMock);
    const pending = get("/v1/graph?limit=10");
    await vi.advanceTimersByTimeAsync(900);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2_000);
    await expect(pending).resolves.toEqual({ nodes: [] });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("surfaces a retryable 503 whose Retry-After is too long to hold the read", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "maintenance" }),
      { status: 503, headers: { "Content-Type": "application/json", "Retry-After": "120" } }));
    vi.stubGlobal("fetch", fetchMock);
    const error = await get("/v1/graph?limit=20").catch(err => err);
    expect(error).toBeInstanceOf(ApiServerError);
    expect((error as ApiServerError).retryAfterSeconds).toBe(120);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("leaves the booting-API 503 to the session's own start-up poll", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "API_STARTING", message: "starting" }, retry_after_seconds: 1 }),
      { status: 503, headers: { "Content-Type": "application/json", "Retry-After": "1" } }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(get("/v1/auth/me?probe=1")).rejects.toBeInstanceOf(ApiServerError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("adaptive backpressure 429", () => {
  const shed = (headers: Record<string, string> = {}, retryAfter = 1) => new Response(
    JSON.stringify({ detail: { message: "Backpressure active for runtime path", path: "graph", reason: "latency_degraded", retry_after_seconds: retryAfter } }),
    { status: 429, headers: { "Content-Type": "application/json", ...headers } },
  );

  it("waits the Retry-After header and retries a shed read", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockResolvedValueOnce(shed({ "Retry-After": "1" })).mockResolvedValueOnce(json({ attack_paths: [] }));
    vi.stubGlobal("fetch", fetchMock);
    const pending = get("/v1/graph/attack-paths?limit=50");
    await vi.advanceTimersByTimeAsync(900);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2_000);
    await expect(pending).resolves.toEqual({ attack_paths: [] });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("falls back to the body's retry_after_seconds when the header is absent", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockResolvedValueOnce(shed({}, 2)).mockResolvedValueOnce(json({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    const pending = get("/v1/graph/views/fix-first");
    await vi.advanceTimersByTimeAsync(1_900);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(pending).resolves.toEqual({ ok: true });
  });

  it("bounds the attempts and surfaces a busy error, not an outage", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockImplementation(async () => shed({ "Retry-After": "1" }));
    vi.stubGlobal("fetch", fetchMock);
    const pending = get("/v1/inventory/summary").catch(err => err);
    await vi.advanceTimersByTimeAsync(30_000);
    const error = await pending;
    expect(error).toBeInstanceOf(ApiRateLimitError);
    expect((error as ApiRateLimitError).retryAfterSeconds).toBe(1);
    expect(isApiBusyError(error)).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("does not hold a read through a long Retry-After", async () => {
    const fetchMock = vi.fn().mockResolvedValue(shed({ "Retry-After": "60" }, 60));
    vi.stubGlobal("fetch", fetchMock);
    const error = await get("/v1/graph/attack-paths?limit=5").catch(err => err);
    expect(isApiBusyError(error)).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("never treats the booting-API 503 or an outage as busy", () => {
    const starting = new ApiServerError("starting", { status: 503, statusText: "", url: "", method: "GET", body: { error: { code: "API_STARTING" } } }, 1);
    const down = new ApiNetworkError("down", { url: "/v1/x", method: "GET" });
    expect(isApiBusyError(starting)).toBe(false);
    expect(isApiBusyError(down)).toBe(false);
  });
});
