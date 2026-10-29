import { queryStaticFindings } from "./static-demo-findings.mjs";
import { ApiError, ApiNetworkError, classifyApiResponse } from "./api-errors";
import { staticDemoDataKey, staticDemoQueryKey } from "./static-demo-key.mjs";

export const STATIC_DEMO_READ_ONLY_MESSAGE =
  "This is a read-only demo — install agent-bom to run it on your own environment.";
export const STATIC_DEMO_QUICKSTART_URL = "https://koda-ai-studio.github.io/agent-bom/getting-started/quickstart/";

/** A write in the public demo; deliberately not a permission error, so views show this message. */
export class StaticDemoReadOnlyError extends ApiError {
  constructor(url: string, method: string) {
    super(STATIC_DEMO_READ_ONLY_MESSAGE, { status: 405, statusText: "Read-only demo", url, method });
    this.name = "StaticDemoReadOnlyError";
  }
}

/** Build-time flag: the export reads shipped sample JSON and never calls an API. */
export function isStaticDemo(): boolean {
  return process.env.NEXT_PUBLIC_STATIC_DEMO === "1";
}

export function staticDemoBasePath(): string {
  return (process.env.NEXT_PUBLIC_BASE_PATH ?? "").replace(/\/$/, "");
}

/** The query carries the original API path only so the generator can record it; static hosts ignore it. */
export function staticDemoDataUrl(apiPath: string, key: string = staticDemoDataKey(apiPath)): string {
  return `${staticDemoBasePath()}/demo-data/${key}.json?path=${encodeURIComponent(apiPath)}`;
}

export async function staticDemoFetch(apiPath: string, init: RequestInit, method: string): Promise<Response> {
  if (method !== "GET") {
    throw new StaticDemoReadOnlyError(apiPath, method);
  }
  const findings = apiPath.split(/[?#]/)[0] === "/v1/findings";
  const queryKey = findings ? null : staticDemoQueryKey(apiPath);
  const url = staticDemoDataUrl(findings ? "/v1/findings" : apiPath);
  let res: Response;
  try {
    // An answer recorded for this exact query wins over the path's default answer.
    const exact = queryKey ? await fetch(staticDemoDataUrl(apiPath, queryKey), { signal: init.signal ?? null, credentials: "same-origin" }) : null;
    res = exact?.ok ? exact : await fetch(url, { signal: init.signal ?? null, credentials: "same-origin" });
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    throw new ApiNetworkError(`Demo data could not be loaded: ${message}`, { url, method, cause });
  }
  if (!res.ok) {
    throw classifyApiResponse(res, { detail: "This view has no sample data in the read-only demo." }, method);
  }
  if (findings) return new Response(JSON.stringify(queryStaticFindings(await res.json(), apiPath)), { status: 200, headers: { "Content-Type": "application/json" } });
  return res;
}
