import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { _clearApiCacheForTests } from "@/lib/api";
import { get, post } from "@/lib/api-transport";
import { ApiNetworkError, ApiServerError, ApiValidationError } from "@/lib/api-errors";

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
      .mockResolvedValueOnce(json({ detail: "bad" }, 422));
    vi.stubGlobal("fetch", fetchMock);
    await expect(get("/v1/a")).rejects.toBeInstanceOf(ApiServerError);
    await expect(get("/v1/b")).rejects.toBeInstanceOf(ApiValidationError);
    expect(fetchMock).toHaveBeenCalledTimes(2);

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
});
