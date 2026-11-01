import { getSessionAuthHeaders } from "./auth";
import { getConfiguredApiUrl } from "./runtime-config";
import { isStaticDemo } from "./static-demo";

export interface GatewayActivity {
  tenant_id: string;
  event_id: string;
  event_type: string;
  event_timestamp: string;
  ingested_at: string;
  ingest_ordinal: number;
  source_id?: string;
  session_id?: string;
  agent_id: string;
  identity_id: string;
  upstream: string;
  tool: string;
  decision: string;
  profile_id: string;
  profile_revision: number;
  blueprint_id: string;
  blueprint_revision: number;
  policy_ids: string[];
  policy_id: string;
  evidence_id: string;
  trace_id: string;
  receipt_trace_id?: string;
  reason_code: string;
  data_action: string;
  development_mode: boolean;
  submission_provenance?: {
    producer_assurance?: string; submission_source_id?: string; submission_session_id?: string;
    reported_source_id?: string; reported_session_id?: string; submitter_principal_id?: string; authentication_method?: string;
  };
}

export interface ActivityPage {
  schema_version: "gateway.activity.stream.v1";
  tenant_id: string;
  events: GatewayActivity[];
  next_cursor: string;
  has_more: boolean;
  retention_floor_ordinal: number;
  latest_ordinal: number;
}

export class ActivityStreamError extends Error {
  constructor(readonly kind: "gap" | "auth" | "unavailable" | "invalid" | "transport") {
    super(kind);
  }
}

/** Complete batches only; retain the caller's cursor on any failed/partial frame. */
export async function* streamGatewayActivity(cursor: string | undefined, signal: AbortSignal, expectedTenant?: string): AsyncGenerator<ActivityPage> {
  if (isStaticDemo()) throw new ActivityStreamError("unavailable");
  let response: Response;
  try {
    response = await fetch(`${getConfiguredApiUrl()}/v1/gateway/feed/stream?limit=200`, {
      credentials: "include", signal,
      headers: { ...getSessionAuthHeaders(), Accept: "text/event-stream", ...(cursor ? { "Last-Event-ID": cursor } : {}) },
    });
  } catch { throw new ActivityStreamError("transport"); }
  if (!response.ok) {
    await response.body?.cancel();
    throw new ActivityStreamError(response.status === 410 || response.status === 400 ? "gap" : [401, 403].includes(response.status) ? "auth" : "unavailable");
  }
  if (!response.body || !response.headers.get("content-type")?.includes("text/event-stream")) {
    await response.body?.cancel();
    throw new ActivityStreamError("invalid");
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "", event = "", id = "", data: string[] = [], size = 0;
  const maxBytes = 32 * 1024 * 1024;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) return;
      buffer += decoder.decode(part.value, { stream: true });
      let end: number;
      while ((end = buffer.indexOf("\n")) !== -1) {
        const raw = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        size += new TextEncoder().encode(raw).length + 1;
        if (size > maxBytes) throw new ActivityStreamError("invalid");
        const line = raw.replace(/\r$/, "");
        if (line) {
          const colon = line.indexOf(":");
          const field = colon < 0 ? line : line.slice(0, colon);
          const value = colon < 0 ? "" : line.slice(colon + 1).replace(/^ /, "");
          if (field === "event") event = value;
          if (field === "id") id = value;
          if (field === "data") data.push(value);
          continue;
        }
        if (data.length) {
          if (event === "gap") throw new ActivityStreamError("gap");
          if (event === "unavailable") throw new ActivityStreamError("unavailable");
          if (event === "reconnect") return;
          let page: ActivityPage;
          try { page = JSON.parse(data.join("\n")); } catch { throw new ActivityStreamError("invalid"); }
          if (!["activity", "checkpoint"].includes(event) || !id || page?.schema_version !== "gateway.activity.stream.v1" || page.next_cursor !== id ||
            typeof page.tenant_id !== "string" || !Array.isArray(page.events) || page.events.length > 500 ||
            typeof page.has_more !== "boolean" || !Number.isSafeInteger(page.latest_ordinal) ||
            page.events.some(row => !row || row.tenant_id !== page.tenant_id || !Number.isSafeInteger(row.ingest_ordinal) ||
              ["event_id", "event_type", "event_timestamp", "ingested_at", "agent_id", "identity_id", "upstream", "tool", "decision", "profile_id", "blueprint_id", "policy_id", "evidence_id", "trace_id", "reason_code", "data_action"].some(key => typeof (row as unknown as Record<string, unknown>)[key] !== "string") ||
              !validActivityOrigin(row) || !Array.isArray(row.policy_ids) || row.policy_ids.some(value => typeof value !== "string"))) {
            throw new ActivityStreamError("invalid");
          }
          if (expectedTenant && page.tenant_id !== expectedTenant) throw new ActivityStreamError("auth");
          yield page;
        }
        event = ""; id = ""; data = []; size = 0;
      }
      if (size + new TextEncoder().encode(buffer).length > maxBytes) throw new ActivityStreamError("invalid");
    }
  } catch (error) {
    if (error instanceof ActivityStreamError) throw error;
    throw new ActivityStreamError("transport");
  } finally {
    try { await reader.cancel(); } finally { reader.releaseLock(); }
  }
}

const FEED_EVENT_TYPES: Record<string, string> = {
  tool_call_authorized: "gateway.tool_call.allowed",
  tool_call_blocked: "gateway.tool_call.blocked",
  data_filter_applied: "gateway.data_filter.applied",
  llm_call: "gateway.llm_call.recorded",
};

const text = (value: unknown): string => typeof value === "string" ? value : "";
const whole = (value: unknown, fallback: number): number => Number.isSafeInteger(value) ? Number(value) : fallback;

/**
 * The fused REST feed (`GET /v1/gateway/feed`) as one activity page. The canonical
 * ledger stream refuses anonymous sessions by design; a no-auth deployment still
 * serves this read-only feed, so the panel renders what the API actually answers
 * instead of a sign-in prompt. Rows without a ledger ordinal keep the server's
 * newest-first order through synthesized descending ordinals.
 */
export async function gatewayFeedSnapshot(signal: AbortSignal, limit = 200): Promise<ActivityPage> {
  if (isStaticDemo()) throw new ActivityStreamError("unavailable");
  let response: Response;
  try {
    response = await fetch(`${getConfiguredApiUrl()}/v1/gateway/feed?limit=${limit}`, { credentials: "include", signal, headers: { ...getSessionAuthHeaders(), Accept: "application/json" } });
  } catch { throw new ActivityStreamError("transport"); }
  if (!response.ok) throw new ActivityStreamError([401, 403].includes(response.status) ? "auth" : "unavailable");
  let body: { tenant_id?: unknown; events?: unknown; has_more?: unknown };
  try { body = await response.json(); } catch { throw new ActivityStreamError("invalid"); }
  if (!body || typeof body.tenant_id !== "string" || !Array.isArray(body.events)) throw new ActivityStreamError("invalid");
  const tenant = body.tenant_id;
  const total = body.events.length;
  const events: GatewayActivity[] = body.events.map((raw, index) => {
    const row = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    const policyIds = Array.isArray(row.policy_ids) ? row.policy_ids.filter((value): value is string => typeof value === "string") : [];
    const stamp = text(row.ts);
    const action = text(row.action_type);
    return {
      tenant_id: tenant,
      event_id: text(row.event_id) || `feed:${action}:${stamp}:${index}`,
      event_type: FEED_EVENT_TYPES[action] ?? `gateway.${action || "event"}`,
      event_timestamp: stamp,
      ingested_at: stamp,
      ingest_ordinal: whole(row.ingest_ordinal, total - index),
      agent_id: text(row.agent),
      identity_id: text(row.identity_id),
      upstream: text(row.upstream),
      tool: text(row.target),
      decision: text(row.decision),
      profile_id: text(row.profile_id),
      profile_revision: whole(row.profile_revision, 0),
      blueprint_id: text(row.blueprint_id),
      blueprint_revision: whole(row.blueprint_revision, 0),
      policy_ids: policyIds,
      policy_id: policyIds[0] ?? "",
      evidence_id: text(row.decision_id),
      trace_id: text(row.trace_id),
      reason_code: text(row.reason_code) || text(row.detail),
      data_action: text(row.data_action),
      development_mode: row.development_mode === true,
    };
  });
  const latest = events.reduce((max, row) => Math.max(max, row.ingest_ordinal), 0);
  return { schema_version: "gateway.activity.stream.v1", tenant_id: tenant, events, next_cursor: "", has_more: body.has_more === true, retention_floor_ordinal: 0, latest_ordinal: latest };
}

/** Read one retained page over the same authenticated canonical contract. */
export async function gatewayActivityPage(cursor: string | undefined, signal: AbortSignal, expectedTenant?: string): Promise<ActivityPage> {
  for await (const page of streamGatewayActivity(cursor, signal, expectedTenant)) return page;
  throw new ActivityStreamError("transport");
}

export function mergeActivity(current: GatewayActivity[], incoming: GatewayActivity[], limit = 1000): GatewayActivity[] {
  const rows = new Map(current.map(row => [row.event_id, row]));
  for (const row of incoming) rows.set(row.event_id, row);
  return [...rows.values()].sort((a, b) => b.ingest_ordinal - a.ingest_ordinal).slice(0, limit);
}

/** Optional fields preserve legacy records; malformed origin metadata cannot become identity. */
function validActivityOrigin(row: GatewayActivity): boolean {
  const bounded = (value: unknown) => value === undefined || (typeof value === "string" && value.length <= 200);
  const provenance = row.submission_provenance;
  return bounded(row.source_id) && bounded(row.session_id) && (provenance == null ||
    (typeof provenance === "object" && !Array.isArray(provenance) &&
      [provenance.producer_assurance, provenance.submission_source_id, provenance.submission_session_id,
        provenance.reported_source_id, provenance.reported_session_id, provenance.submitter_principal_id,
        provenance.authentication_method].every(bounded)));
}
