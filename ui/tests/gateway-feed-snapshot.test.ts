import { afterEach, describe, expect, it, vi } from "vitest";
import { ActivityStreamError, gatewayFeedSnapshot } from "@/lib/gateway-activity";

const feedEvent = (overrides: Record<string, unknown> = {}) => ({
  producer_assurance: "unknown", event_id: "demo-estate-gateway:2026-11-01:1:filesystem-server.read_file", decision_id: "",
  ts: "2026-11-01T19:19:23+00:00", agent: "Cursor", identity_id: "", profile_id: "", profile_revision: 0, blueprint_id: "", blueprint_revision: 0,
  policy_ids: ["policy-a"], reason_code: "policy_allow", development_mode: false, action_type: "tool_call_authorized", target: "filesystem-server.read_file",
  upstream: "", decision: "allow", data_action: "", policy_source: "", trace_id: "", detail: "authorized", tenant: "default", shadow: false, source: "proxy",
  ingest_ordinal: null, ...overrides,
});
const body = (events: unknown[]) => JSON.stringify({ schema_version: "gateway.feed.v1", tenant_id: "default", generated_at: "2026-11-01T19:20:00+00:00", count: events.length, events, next_cursor: "", has_more: false, source: "degraded_single_process" });
afterEach(() => vi.unstubAllGlobals());

describe("REST feed snapshot for sessions the ledger stream refuses", () => {
  it("maps fused feed events onto activity rows with a stable descending order", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(body([
      feedEvent(),
      feedEvent({ event_id: "e2", action_type: "tool_call_blocked", decision: "deny", target: "shell.run", ingest_ordinal: 7 }),
      feedEvent({ event_id: "e3", action_type: "data_filter_applied", data_action: "redact" }),
      feedEvent({ event_id: "", action_type: "llm_call", target: "anthropic/model-x", detail: "$1.00" }),
    ]), { headers: { "content-type": "application/json" } })));
    const page = await gatewayFeedSnapshot(new AbortController().signal);
    expect(page.tenant_id).toBe("default");
    expect(page.events.map(row => row.event_type)).toEqual(["gateway.tool_call.allowed", "gateway.tool_call.blocked", "gateway.data_filter.applied", "gateway.llm_call.recorded"]);
    expect(page.events[0]).toMatchObject({ agent_id: "Cursor", tool: "filesystem-server.read_file", decision: "allow", policy_id: "policy-a", event_timestamp: "2026-11-01T19:19:23+00:00" });
    // Server order is newest first; synthesized ordinals keep it after a merge sort.
    expect(page.events.map(row => row.ingest_ordinal)).toEqual([4, 7, 2, 1]);
    expect(page.events[3]?.event_id).not.toBe("");
    expect(page.has_more).toBe(false);
  });
  it.each([[401, "auth"], [403, "auth"], [503, "unavailable"]])("fails closed on HTTP %s", async (status, kind) => {
    vi.stubGlobal("fetch", async () => new Response("x", { status: Number(status) }));
    await expect(gatewayFeedSnapshot(new AbortController().signal)).rejects.toMatchObject({ kind });
  });
  it("rejects a body that is not the feed contract", async () => {
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ events: "nope" }), { headers: { "content-type": "application/json" } }));
    await expect(gatewayFeedSnapshot(new AbortController().signal)).rejects.toBeInstanceOf(ActivityStreamError);
  });
});
