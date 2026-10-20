import { NextRequest, NextResponse } from "next/server";

/** Server-only configuration: never derive an upstream from request input. */
export function runtimeApiOrigin(): string {
  const env = process.env;
  const raw = env.AGENT_BOM_API_URL?.trim() || env.NEXT_PUBLIC_API_URL?.trim() || "http://localhost:8422";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Invalid server API origin");
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash) {
    throw new Error("Invalid server API origin");
  }
  return url.origin;
}

const READY_TTL_MS = 5_000;
const PROBE_TIMEOUT_MS = 1_500;
const RETRY_AFTER_SECONDS = 2;
const readyUntil = new Map<string, number>();

export function _resetUpstreamReadiness(): void {
  readyUntil.clear();
}

/**
 * A rewrite to an API that is not listening yet surfaces as an opaque 500.
 * Only a refused/unresolved connection means "starting"; a slow or erroring API
 * answered, so its own response is forwarded.
 */
async function upstreamAccepting(origin: string): Promise<boolean> {
  if ((readyUntil.get(origin) ?? 0) > Date.now()) return true;
  try {
    await fetch(`${origin}/health`, { cache: "no-store", signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
  } catch (error) {
    const name = error instanceof Error || error instanceof DOMException ? error.name : "";
    if (name !== "TimeoutError" && name !== "AbortError") return false;
  }
  readyUntil.set(origin, Date.now() + READY_TTL_MS);
  return true;
}

function apiStarting(): NextResponse {
  return NextResponse.json(
    { error: { code: "API_STARTING", message: "The control plane API is starting." }, retry_after_seconds: RETRY_AFTER_SECONDS },
    { status: 503, headers: { "Retry-After": String(RETRY_AFTER_SECONDS), "Cache-Control": "no-store" } },
  );
}

export async function proxyApiRequest(request: NextRequest): Promise<NextResponse> {
  const { pathname, search } = request.nextUrl;
  if (!(pathname === '/v1' || pathname.startsWith('/v1/') || pathname === '/health' ||
        pathname === '/version' || pathname === '/ws' || pathname.startsWith('/ws/'))) {
    return NextResponse.next();
  }
  let destination: URL;
  try {
    destination = new URL(runtimeApiOrigin());
  } catch {
    return NextResponse.json({ error: "API routing is unavailable" }, { status: 503 });
  }
  if (!(await upstreamAccepting(destination.origin))) return apiStarting();
  destination.pathname = pathname;
  destination.search = search;
  return NextResponse.rewrite(destination);
}
