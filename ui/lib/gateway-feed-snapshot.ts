import { getSessionAuthHeaders } from "./auth";
import { ActivityStreamError, type ActivityPage, type GatewayActivity } from "./gateway-activity";
import { getConfiguredApiUrl } from "./runtime-config";
import { isStaticDemo } from "./static-demo";

const EVENT_TYPES: Record<string, string> = {
  tool_call_authorized: "gateway.tool_call.allowed",
  tool_call_blocked: "gateway.tool_call.blocked",
  data_filter_applied: "gateway.data_filter.applied",
  llm_call: "gateway.llm_call.recorded",
};
/** Activity field ← feed field, for the string fields copied as-is. */
const COPY: [keyof GatewayActivity, string][] = [
  ["agent_id", "agent"], ["identity_id", "identity_id"], ["upstream", "upstream"], ["tool", "target"], ["decision", "decision"],
  ["profile_id", "profile_id"], ["blueprint_id", "blueprint_id"], ["evidence_id", "decision_id"], ["trace_id", "trace_id"], ["data_action", "data_action"],
];
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
  const events = body.events.map((raw, index): GatewayActivity => {
    const row = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    const policy_ids = Array.isArray(row.policy_ids) ? row.policy_ids.filter((value): value is string => typeof value === "string") : [];
    const stamp = text(row.ts);
    const action = text(row.action_type);
    const copied = Object.fromEntries(COPY.map(([key, source]) => [key, text(row[source])]));
    return {
      ...copied,
      tenant_id: tenant,
      event_id: text(row.event_id) || `feed:${action}:${stamp}:${index}`,
      event_type: EVENT_TYPES[action] ?? `gateway.${action || "event"}`,
      event_timestamp: stamp,
      ingested_at: stamp,
      ingest_ordinal: whole(row.ingest_ordinal, total - index),
      profile_revision: whole(row.profile_revision, 0),
      blueprint_revision: whole(row.blueprint_revision, 0),
      policy_ids,
      policy_id: policy_ids[0] ?? "",
      reason_code: text(row.reason_code) || text(row.detail),
      development_mode: row.development_mode === true,
    } as GatewayActivity;
  });
  const latest = events.reduce((max, row) => Math.max(max, row.ingest_ordinal), 0);
  return { schema_version: "gateway.activity.stream.v1", tenant_id: tenant, events, next_cursor: "", has_more: body.has_more === true, retention_floor_ordinal: 0, latest_ordinal: latest };
}
