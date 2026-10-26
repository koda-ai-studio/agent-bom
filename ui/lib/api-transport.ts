import { getSessionAuthHeaders } from "./auth";
import { getConfiguredApiUrl } from "./runtime-config";
import { isStaticDemo, staticDemoFetch } from "./static-demo";

import { cachedGet, clearCache as _clearCache, invalidate as _invalidate } from "./api-cache";
import type { CacheOptions } from "./api-cache";

// ─── Fetch helpers ────────────────────────────────────────────────────────────
//
// Closes #1956. All five wrappers below funnel through ApiError-typed throws
// (lib/api-errors.ts) and the GET wrapper is memoized + dedup'd via
// lib/api-cache.ts. Mutations (post/postVoid/put/del) invalidate cache
// prefixes so a write to /v1/scan/{id} flushes /v1/scan and any nested
// children without each call site having to remember.

import { ApiNetworkError, ApiRateLimitError, ApiServerError, classifyApiResponse, isApiStartingError } from "./api-errors";

// Cache keys and invalidation prefixes must share this format.
const getCacheKey = (path: string) => `GET ${path}`;

const FETCH_TIMEOUT_MS = 30_000;
export const BOOTSTRAP_TIMEOUT_MS = 5_000;
export const DEMO_STORY_TIMEOUT_MS = 90_000;

export function withTimeout(timeoutMs: number = FETCH_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

type GetOptions = CacheOptions & { timeoutMs?: number; signal?: AbortSignal };

async function _parseBody(res: Response): Promise<unknown> {
  // Only called on the error path; caller never reads the body again, so we
  // can consume the stream directly. Avoid `.clone()` because test mocks
  // and partial Response shims may not implement it.
  try {
    return await res.json();
  } catch {
    try {
      return await res.text();
    } catch {
      return undefined;
    }
  }
}

export async function _doFetch(path: string, init: RequestInit, method: string): Promise<Response> {
  if (isStaticDemo()) return staticDemoFetch(path, init, method);
  const url = `${getConfiguredApiUrl()}${path}`;
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    throw new ApiNetworkError(`Network request failed: ${message}`, { url, method, cause });
  }
  if (!res.ok) {
    const body = await _parseBody(res);
    throw classifyApiResponse(res, body, method);
  }
  return res;
}

/** Cache-prefix invalidation rules for write paths. */
function _invalidationsFor(path: string): string[] {
  // Any write to /v1/<resource>[/<id>][/...] flushes /v1/<resource> entirely.
  // Coarse on purpose: getting a stale /v1/scan list right after the user
  // submits a scan is the failure mode this is here to prevent.
  const match = /^\/v1\/[^/?]+/.exec(path);
  return match ? [match[0]] : [];
}

function _runInvalidations(path: string): void {
  for (const prefix of _invalidationsFor(path)) {
    _invalidate(getCacheKey(prefix));
  }
}

/** A session change, even a failed one, may change the principal; no prior response is reusable. */
export function _sessionChange(request: () => Promise<void>): Promise<void> {
  _clearCache();
  return request().finally(_clearCache);
}

/** Pause before the single retry of an idempotent read, with jitter so tabs do not stampede. */
export const TRANSIENT_RETRY_DELAY_MS = 250;

/**
 * A failure the next attempt can plausibly avoid: a dropped connection
 * (ECONNRESET surfaces as a fetch TypeError), or a 500/502/503/504 that a
 * proxy or gateway produced without an API body. Aborts, timeouts and
 * API-reported errors (a JSON body) are answers, not transport failures.
 */
export function isTransientReadFailure(error: unknown): boolean {
  if (error instanceof ApiNetworkError) {
    const cause = (error as { cause?: unknown }).cause;
    const name = cause instanceof Error || cause instanceof DOMException ? cause.name : "";
    return name !== "AbortError" && name !== "TimeoutError";
  }
  if (!(error instanceof ApiServerError)) return false;
  const apiAnswered = error.body !== undefined && typeof error.body !== "string";
  return [500, 502, 503, 504].includes(error.status) && !apiAnswered;
}

/** Longest Retry-After an idempotent read waits through before surfacing the 503/429 instead. */
export const MAX_RETRY_AFTER_SECONDS = 5;

/** Retries of a read the API shed under backpressure (429) before the page shows its busy state. */
export const MAX_RATE_LIMIT_RETRIES = 3;

/**
 * How long to wait before retry number `retriesSoFar + 1`, or null when the
 * failure is an answer or the retry budget is spent. Transient and retryable-503
 * failures get one retry; a 429 gets up to MAX_RATE_LIMIT_RETRIES.
 */
export function readRetryDelayMs(error: unknown, retriesSoFar = 0): number | null {
  const jitter = TRANSIENT_RETRY_DELAY_MS * Math.random();
  if (error instanceof ApiRateLimitError) {
    if (retriesSoFar >= MAX_RATE_LIMIT_RETRIES) return null;
    const seconds = error.retryAfterSeconds ?? 2 ** retriesSoFar;
    return seconds <= MAX_RETRY_AFTER_SECONDS ? Math.max(seconds * 1000, TRANSIENT_RETRY_DELAY_MS) + jitter : null;
  }
  if (retriesSoFar >= 1) return null;
  if (error instanceof ApiServerError && error.status === 503 && error.retryAfterSeconds !== undefined) {
    if (isApiStartingError(error)) return null;
    return error.retryAfterSeconds <= MAX_RETRY_AFTER_SECONDS ? error.retryAfterSeconds * 1000 + jitter : null;
  }
  return isTransientReadFailure(error) ? TRANSIENT_RETRY_DELAY_MS + jitter : null;
}

export async function get<T>(path: string, options: GetOptions = {}): Promise<T> {
  const { timeoutMs, signal, ...cacheOptions } = options;
  const key = getCacheKey(path);
  const attempt = async () => {
    const res = await _doFetch(path, {
      credentials: "include",
      headers: getSessionAuthHeaders(),
      signal: signal ? AbortSignal.any([signal, withTimeout(timeoutMs ?? FETCH_TIMEOUT_MS)]) : withTimeout(timeoutMs ?? FETCH_TIMEOUT_MS),
    }, "GET");
    return res.json() as Promise<T>;
  };
  const fetcher = async (): Promise<T> => {
    for (let retries = 0; ; retries += 1) {
      try {
        return await attempt();
      } catch (error) {
        const delayMs = signal?.aborted ? null : readRetryDelayMs(error, retries);
        if (delayMs === null) throw error;
        await new Promise(resolve => setTimeout(resolve, delayMs));
        if (signal?.aborted) throw error;
      }
    }
  };
  // A caller-owned cancellation must never abort another subscriber.
  return signal ? fetcher() : cachedGet<T>(key, fetcher, cacheOptions);
}

export async function post<T>(path: string, body: unknown, headers: Record<string, string> = {}, signal?: AbortSignal, timeoutMs = FETCH_TIMEOUT_MS): Promise<T> {
  const res = await _doFetch(path, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...getSessionAuthHeaders(), ...headers },
    body: JSON.stringify(body),
    signal: signal ? AbortSignal.any([signal, withTimeout(timeoutMs)]) : withTimeout(timeoutMs),
  }, "POST");
  _runInvalidations(path);
  return res.json() as Promise<T>;
}

export function mutationIdempotencyKey(prefix: string): string {
  const random = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${random}`;
}

export async function postVoid(path: string, body: unknown, headers: Record<string, string> = {}): Promise<void> {
  await _doFetch(path, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...getSessionAuthHeaders(), ...headers },
    body: JSON.stringify(body),
    signal: withTimeout(),
  }, "POST");
  _runInvalidations(path);
}

export async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await _doFetch(path, {
    method: "PUT",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...getSessionAuthHeaders() },
    body: JSON.stringify(body),
    signal: withTimeout(),
  }, "PUT");
  _runInvalidations(path);
  return res.json() as Promise<T>;
}

export async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await _doFetch(path, {
    method: "PATCH",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...getSessionAuthHeaders() },
    body: JSON.stringify(body),
    signal: withTimeout(),
  }, "PATCH");
  _runInvalidations(path);
  return res.json() as Promise<T>;
}

export async function del(path: string): Promise<void> {
  await _doFetch(path, {
    method: "DELETE",
    credentials: "include",
    headers: getSessionAuthHeaders(),
    signal: withTimeout(),
  }, "DELETE");
  _runInvalidations(path);
}

export async function getBlob(path: string, headers: Record<string, string> = {}): Promise<Blob> {
  const res = await _doFetch(path, {
    credentials: "include",
    headers: { ...getSessionAuthHeaders(), ...headers },
    signal: withTimeout(),
  }, "GET");
  return res.blob();
}
